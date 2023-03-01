//  PORTS.rs
//    by Lut99
// 
//  Created:
//    23 Nov 2022, 11:30:05
//  Last edited:
//    28 Nov 2022, 14:10:03
//  Auto updated?
//    Yes
// 
//  Description:
//!   Defines the PortAllocator, which is in charge of deciding which
//!   ports are available for, well, allocation.
// 


/***** LIBRARY *****/
/// The PortAllocator is in charge of allocating ports from a possible range.
#[derive(Clone, Debug)]
pub struct PortAllocator {
    /// The current index in the range of ports.
    index : u16,
    /// The end of the range.
    end   : u16,
}

impl PortAllocator {
    /// Constructor for the PortAllocator.
    /// 
    /// # Arguments
    /// - `start`: The first port in the range we may allocate from (inclusive).
    /// - `end`: The last port in the range we may allocate from (inclusive).
    /// 
    /// # Returns
    /// A new PortAllocator ready for allocation.
    /// 
    /// # Panics
    /// This function panics if `start` > `end`.
    pub fn new(start: u16, end: u16) -> Self {
        if start > end { panic!("Start cannot be larger than end ({start} > {end})"); }
        Self {
            index : start,
            end
        }
    }



    /// Gets a new port from the PortAllocator.
    /// 
    /// # Returns
    /// A new port if there was still any left to allocate.
    pub fn allocate(&mut self) -> Option<u16> {
        if self.index <= self.end {
            let res: u16 = self.index;
            self.index += 1;
            Some(res)
        } else {
            None
        }
    }
}
