use super::{CanonicalOption, ComponentSection, SectionId};
use crate::encoders;

/// An encoder for the component adapter function section.
///
/// # Example
///
/// ```rust
/// use wasm_encoder::component::{Component, AdapterFunctionSection, CanonicalOption};
///
/// // This assumes there is an adapter function type with
/// // index 0 and a target function with index 0.
/// let mut adapters = AdapterFunctionSection::new();
/// adapters.adapter(0, &[CanonicalOption::UTF8], 0);
///
/// let mut component = Component::new();
/// component.section(&adapters);
///
/// let bytes = component.finish();
/// ```
#[derive(Clone, Debug, Default)]
pub struct AdapterFunctionSection {
    bytes: Vec<u8>,
    num_added: u32,
}

impl AdapterFunctionSection {
    /// Create a new component adapter function section encoder.
    pub fn new() -> Self {
        Self::default()
    }

    /// The number of adapter functions in the section.
    pub fn len(&self) -> u32 {
        self.num_added
    }

    /// Determines if the section is empty.
    pub fn is_empty(&self) -> bool {
        self.num_added == 0
    }

    /// Define an adapter function in the adapter function section.
    ///
    /// `type_index` must be to an adapter function type.
    /// `target_index` must be to a function.
    pub fn adapter(
        &mut self,
        type_index: u32,
        options: &[CanonicalOption],
        target_index: u32,
    ) -> &mut Self {
        self.bytes.extend(encoders::u32(type_index));
        self.bytes.push(0x00); // This byte is a placeholder for future cases.
        self.bytes
            .extend(encoders::u32(u32::try_from(options.len()).unwrap()));
        for option in options {
            option.encode(&mut self.bytes);
        }
        self.bytes.extend(encoders::u32(target_index));
        self
    }
}

impl ComponentSection for AdapterFunctionSection {
    fn id(&self) -> u8 {
        SectionId::AdapterFunction.into()
    }

    fn encode<S>(&self, sink: &mut S)
    where
        S: Extend<u8>,
    {
        let num_added = encoders::u32(self.num_added);
        let n = num_added.len();
        sink.extend(
            encoders::u32(u32::try_from(n + self.bytes.len()).unwrap())
                .chain(num_added)
                .chain(self.bytes.iter().copied()),
        );
    }
}
