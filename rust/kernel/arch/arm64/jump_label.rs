// SPDX-License-Identifier: GPL-2.0

// Copyright (C) 2024 Google LLC.

//! Arm64 Rust implementation of jump_label.h

/// arm64 implementation of arch_static_branch without asmgoto
#[macro_export]
#[cfg(target_arch = "aarch64")]
#[cfg(not(CONFIG_HAVE_RUST_ASM_GOTO))]
macro_rules! arch_static_branch {
    ($key:path, $keytyp:ty, $field:ident, $branch:expr) => {{
        let mut output = 1u32;

        core::arch::asm!(
            r#"
            1: nop

            .pushsection __jump_table,  "aw"
            .align 3
            .long 1b - ., 3f - .
            .quad {0} + {1} + {2} - .
            .popsection

            2: mov {3:w}, 0
            3:
            "#,
            sym $key,
            const ::core::mem::offset_of!($keytyp, $field),
            const $crate::arch::bool_to_int($branch),
            inout(reg) output
        );

        output != 0
    }};
}

/// arm64 implementation of arch_static_branch
#[macro_export]
#[cfg(target_arch = "aarch64")]
#[cfg(CONFIG_HAVE_RUST_ASM_GOTO)]
macro_rules! arch_static_branch {
    ($key:path, $keytyp:ty, $field:ident, $branch:expr) => {'my_label: {
        core::arch::asm!(
            r#"
            1: nop

            .pushsection __jump_table,  "aw"
            .align 3
            .long 1b - ., {0} - .
            .quad {1} + {2} + {3} - .
            .popsection
            "#,
            label {
                break 'my_label true;
            },
            sym $key,
            const ::core::mem::offset_of!($keytyp, $field),
            const $crate::arch::bool_to_int($branch),
        );

        break 'my_label false;
    }};
}

pub use arch_static_branch;
