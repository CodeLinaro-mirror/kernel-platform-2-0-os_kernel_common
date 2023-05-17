// SPDX-License-Identifier: GPL-2.0

//! This module defines the `Process` type, which represents a process using a particular binder
//! context.
//!
//! The `Process` object keeps track of all of the resources that this process owns in the binder
//! context.
//!
//! There is one `Process` object for each binder fd that a process has opened, so processes using
//! several binder contexts have several `Process` objects. This ensures that the contexts are
//! fully separated.

use kernel::{
    bindings,
    cred::Credential,
    file::{self, File, IoctlCommand, IoctlHandler, PollTable},
    io_buffer::IoBufferWriter,
    linked_list::{GetLinks, Links},
    mm,
    prelude::*,
    sync::{Arc, ArcBorrow, SpinLock},
    task::Task,
    types::ARef,
    user_ptr::{UserSlicePtr, UserSlicePtrReader},
    workqueue::{self, Work},
};

use crate::{context::Context, defs::*};

const PROC_DEFER_FLUSH: u8 = 1;
const PROC_DEFER_RELEASE: u8 = 2;

/// The fields of `Process` protected by the spinlock.
pub(crate) struct ProcessInner {
    is_dead: bool,

    /// Bitmap of deferred work to do.
    defer_work: u8,
}

impl ProcessInner {
    fn new() -> Self {
        Self {
            is_dead: false,
            defer_work: 0,
        }
    }
}

/// A process using binder.
///
/// Strictly speaking, there can be multiple of these per process. There is one for each binder fd
/// that a process has opened, so processes using several binder contexts have several `Process`
/// objects. This ensures that the contexts are fully separated.
#[pin_data]
pub(crate) struct Process {
    pub(crate) ctx: Arc<Context>,

    // The task leader (process).
    pub(crate) task: ARef<Task>,

    // Credential associated with file when `Process` is created.
    pub(crate) cred: ARef<Credential>,

    #[pin]
    pub(crate) inner: SpinLock<ProcessInner>,

    // Work node for deferred work item.
    #[pin]
    defer_work: Work<Arc<Process>>,

    // Links for process list in Context.
    links: Links<Process>,
}

kernel::impl_has_work! {
    impl HasWork<Arc<Process>> for Process { self.defer_work }
}

impl GetLinks for Process {
    type EntryType = Process;
    fn get_links(data: &Process) -> &Links<Process> {
        &data.links
    }
}

impl workqueue::ArcWorkItem for Process {
    fn run(self: Arc<Self>) {
        let defer;
        {
            let mut inner = self.inner.lock();
            defer = inner.defer_work;
            inner.defer_work = 0;
        }

        if defer & PROC_DEFER_FLUSH != 0 {
            self.deferred_flush();
        }
        if defer & PROC_DEFER_RELEASE != 0 {
            self.deferred_release();
        }
    }
}

impl Process {
    fn new(ctx: Arc<Context>, cred: ARef<Credential>) -> Result<Arc<Self>> {
        let process = Arc::pin_init(pin_init!(Process {
            ctx,
            cred,
            inner <- kernel::new_spinlock!(ProcessInner::new(), "Process::inner"),
            task: kernel::current!().group_leader().into(),
            defer_work <- kernel::new_work!(),
            links: Links::new(),
        }))?;

        process.ctx.register_process(process.clone());

        Ok(process)
    }

    fn version(&self, data: UserSlicePtr) -> Result {
        data.writer().write(&BinderVersion::current())
    }

    fn deferred_flush(&self) {
        // NOOP for now.
    }

    fn deferred_release(self: Arc<Self>) {
        {
            let mut inner = self.inner.lock();
            inner.is_dead = true;
        }

        self.ctx.deregister_process(&self);
    }

    pub(crate) fn flush(this: ArcBorrow<'_, Process>) -> Result {
        let should_schedule;
        {
            let mut inner = this.inner.lock();
            should_schedule = inner.defer_work == 0;
            inner.defer_work |= PROC_DEFER_FLUSH;
        }

        if should_schedule {
            // Ignore failures to schedule to the workqueue. Those just mean that we're already
            // scheduled for execution.
            let _ = workqueue::system().enqueue(Arc::from(this));
        }
        Ok(())
    }
}

impl IoctlHandler for Process {
    type Target<'a> = ArcBorrow<'a, Process>;

    fn write(
        _this: ArcBorrow<'_, Process>,
        _file: &File,
        _cmd: u32,
        _reader: &mut UserSlicePtrReader,
    ) -> Result<i32> {
        Err(EINVAL)
    }

    fn read_write(
        this: ArcBorrow<'_, Process>,
        _file: &File,
        cmd: u32,
        data: UserSlicePtr,
    ) -> Result<i32> {
        match cmd {
            bindings::BINDER_VERSION => this.version(data)?,
            _ => return Err(EINVAL),
        }
        Ok(0)
    }
}

#[vtable]
impl file::Operations for Process {
    type Data = Arc<Self>;
    type OpenData = Arc<Context>;

    fn open(ctx: &Arc<Context>, file: &File) -> Result<Self::Data> {
        Self::new(ctx.clone(), ARef::from(file.cred()))
    }

    fn release(this: Self::Data, _file: &File) {
        let should_schedule;
        {
            let mut inner = this.inner.lock();
            should_schedule = inner.defer_work == 0;
            inner.defer_work |= PROC_DEFER_RELEASE;
        }

        if should_schedule {
            // Ignore failures to schedule to the workqueue. Those just mean that we're already
            // scheduled for execution.
            let _ = workqueue::system().enqueue(this);
        }
    }

    fn ioctl(this: ArcBorrow<'_, Process>, file: &File, cmd: &mut IoctlCommand) -> Result<i32> {
        cmd.dispatch::<Self>(this, file)
    }

    fn compat_ioctl(
        this: ArcBorrow<'_, Process>,
        file: &File,
        cmd: &mut IoctlCommand,
    ) -> Result<i32> {
        cmd.dispatch::<Self>(this, file)
    }

    fn mmap(_this: ArcBorrow<'_, Process>, _file: &File, _vma: &mut mm::virt::Area) -> Result {
        Err(EINVAL)
    }

    fn poll(_this: ArcBorrow<'_, Process>, _file: &File, _table: &PollTable) -> Result<u32> {
        Err(EINVAL)
    }
}
