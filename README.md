# pprof

This is a pprof tool that delivers a subset of the features of "go tool pprof".
It uses https://github.com/gimli-rs/addr2line to achieve faster symbolization
performance than the official tooling.


## Usage
To use the tool, you need a pprof profile and a binary with debug symbols.
Usage looks like this:

	[~/work/sophon/src/rust] (feat/heap-profiling) $ pprof ~/work/sophon/src/rust/target/release/indexer /tmp/profiles-kk/heap-20260211T001650.pb.gz
	Loading binary: /home/wyatt/work/sophon/src/rust/target/release/indexer
	DWARF loaded
	Loading profile: /tmp/profiles-kk/heap-20260211T001650.pb.gz
	Profile loaded: 434 functions, 1500.1MB total bytes
	Type 'help' for available commands.
	(pprof) top 20
				flat  flat%        cum   cum%  function
		736.00MB  49.1%   736.00MB  49.1%  <lance_file::io::LanceEncodingsIo as lance_encoding::EncodingsIo>::submit_req...
		302.45MB  20.2%  1092.45MB  72.8%  <alloc::vec::Vec<T> as alloc::vec::spec_from_iter_nested::SpecFromIterNested<...
		272.00MB  18.1%   272.00MB  18.1%  bytes::bytes_mut::BytesMut::with_capacity
		120.50MB   8.0%   120.50MB   8.0%  mallocx
		19.04MB   1.3%    19.04MB   1.3%  irallocx_prof
		13.00MB   0.9%    14.00MB   0.9%  alloc::boxed::Box<T,A>::try_new_uninit_in
		11.00MB   0.7%    11.00MB   0.7%  alloc::sync::Arc<[T],A>::allocate_for_slice_in::{{closure}}
			9.50MB   0.6%    17.50MB   1.2%  prost::encoding::message::merge_repeated
			5.00MB   0.3%     5.00MB   0.3%  prost::encoding::<impl prost::encoding::sealed::BytesAdapter for alloc::vec::...
			2.13MB   0.1%     2.13MB   0.1%  lance_table::utils::stream::apply_row_id_and_deletes
			2.00MB   0.1%     2.50MB   0.2%  alloc::boxed::Box<T>::new
			2.00MB   0.1%     2.00MB   0.1%  prost::encoding::uint64::merge_repeated::{{closure}}
			1.50MB   0.1%     1.50MB   0.1%  calloc
			1.00MB   0.1%     1.00MB   0.1%  lance_index::vector::hnsw::select_neighbors_heuristic
			1.00MB   0.1%     1.00MB   0.1%  <T as alloc::slice::<impl [T]>::to_vec_in::ConvertVec>::to_vec
			0.75MB   0.0%     1.25MB   0.1%  lance::io::exec::filtered_read::FilteredReadStream::plan_scan::{{closure}}::{...
			0.71MB   0.0%     0.71MB   0.0%  arrow_array::builder::primitive_builder::PrimitiveBuilder<T>::with_capacity
			0.50MB   0.0%     0.50MB   0.0%  lance_io::scheduler::FileScheduler::submit_request
			0.00MB   0.0%   747.09MB  49.8%  lance::index::create::CreateIndexBuilder::execute_uncommitted::{{closure}}::{...
			0.00MB   0.0%     0.50MB   0.0%  <crossbeam_deque::deque::Injector<T> as core::default::Default>::default
	(pprof)


Listing is also supported:

    (pprof) list select_neighbors_heuristic
    
    ================================================================================
    File: /mnt/work/home/wyatt/work/sophon/src/lance/rust/lance-index/src/vector/hnsw.rs
      1.00MB  lance_index::vector::hnsw::select_neighbors_heuristic
    ================================================================================
                        71:     candidates.sort_unstable();
                        72: 
      1.00MB   1.00MB    73:     let mut results: Vec<OrderedNode> = Vec::with_capacity(k);
                        74:     for u in candidates.iter() {
                        75:         if results.len() >= k {
                        76:             break;
    (pprof)
    
    
This tool works great with llms. Try telling your LLM to use it to debug some dumps, and it will figure out how.
