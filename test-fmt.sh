#!/usr/bin/bash

#set -x

fmtvers=(
	#"8.1.1"
	#"9.1.0"
	"10.1.0"
	"10.1.1"
	"10.2.0"
	#"11.0.2"
	#"11.1.1"
	#"11.1.3"
	#"11.1.4"
	#"11.2.0"
	#"12.1.0"
)

compilers_clang=(
	"/usr/bin/clang++"
	#"/usr/lib/llvm17/bin/clang++"
	#"/usr/lib/llvm18/bin/clang++"
	#"/usr/lib/llvm19/bin/clang++"
	#"/usr/lib/llvm20/bin/clang++"
	#"/usr/lib/llvm21/bin/clang++"
)

compilers_aocc=(
	#"/home/swooshy/devstuff/aocc/aocc-compiler-4.1.0/bin/clang++"
	#"/home/swooshy/devstuff/aocc/aocc-compiler-4.2.0/bin/clang++"
	#"/home/swooshy/devstuff/aocc/aocc-compiler-5.0.0/bin/clang++"
	#"/home/swooshy/devstuff/aocc/aocc-compiler-5.1.0/bin/clang++"
	#"/home/swooshy/devstuff/aocc/aocc-compiler-5.2.0/bin/clang++"
)

compilers_gcc=(
	#"/usr/bin/g++"
	#"/usr/bin/g++-4.7"
	#"/usr/bin/g++-5"
	#"/usr/bin/g++-6"
	#"/usr/bin/g++-7"
	#"/usr/bin/g++-8"
	#"/usr/bin/g++-9"
	#"/usr/bin/g++-10"
	#"/usr/bin/g++-11"
	#"/usr/bin/g++-12"
	#"/usr/bin/g++-13"
	#"/usr/bin/g++-14"
	#"/usr/bin/g++-15"
)

llvm_tools=(
	clang
	clang++
	clang-scan-deps
	ld.lld
	lld
	llvm-addr2line
	llvm-ar
	llvm-dlltool
	llvm-mt
	llvm-nm
	llvm-objcopy
	llvm-objdump
	llvm-ranlib
	llvm-readelf
	llvm-strip
)

declare -A compilers
declare -A compiler_dirs
declare -A compiler_tools

for compiler_path in "${compilers_clang[@]}"; do
	compiler_version="$("${compiler_path}" --version | grep -Po --color=never "(?<=clang version )[^ ]+")"
	compiler="clang${compiler_version}"
	compilers["${compiler}"]="${compiler_path}"
done

for compiler_path in "${compilers_aocc[@]}"; do
	compiler_version="$("${compiler_path}" --version | grep -Po --color=never "(?<=AOCC_)[^-]+")"
	compiler="aocc${compiler_version}"
	compilers["${compiler}"]="${compiler_path}"
done

for compiler_path in "${compilers_gcc[@]}"; do
	compiler_version="$("${compiler_path}" --version | grep -Po --color=never "(?<=g\+\+(-[0-9]{2})? \([^\)]{1,32}\) )[^ ]+")"
	compiler="gcc${compiler_version}"
	compilers["${compiler}"]="${compiler_path}"
done

for compiler in "${!compilers[@]}"; do
	compiler_path="${compilers["$compiler"]}"

	compiler_dir="$(dirname "$(dirname "${compiler_path}")")"
	compiler_dirs["${compiler}"]="${compiler_dir}"

	for compiler_tool in "${llvm_tools[@]}"; do
		compiler_tool_name="${compiler_tool//-/_}"
		compiler_tool_name="${compiler_tool_name//./_}"
		compiler_tool_name="${compiler_tool_name//+/_}"
		compiler_tool_name="${compiler},${compiler_tool_name}"
		if [ -x "${compiler_dir}/bin/${compiler_tool}" ]; then
			compiler_tools["${compiler_tool_name}"]="${compiler_dir}/bin/${compiler_tool}"
		else
			compiler_tools["${compiler_tool_name}"]="/usr/bin/${compiler_tool}"
		fi
	done
done

builds_dir="/home/swooshy/devstuff/renci/builds/host-qtcreator/clang16-libstdcxx/re_audit_amqp-variants"

mkdir -p "${builds_dir}"

rm -f "${builds_dir}/Makefile"

for compiler in "${!compilers[@]}"; do
	compiler_path="${compilers["$compiler"]}"
	compiler_dir="${compiler_dirs["$compiler"]}"

	for fmtver in "${fmtvers[@]}"; do

		build_suffix="${compiler}-fmt${fmtver}"

		mkdir -p "${builds_dir}/${build_suffix}"
		cd "${builds_dir}/${build_suffix}"
		cmake \
			-S /home/swooshy/devstuff/renci/irods_rule_engine_plugin_audit_amqp \
			-DBUILD_DOCS:BOOL=OFF \
			-DCMAKE_ADDR2LINE:FILEPATH="${compiler_tools["${compiler},llvm_addr2line"]}" \
			-DCMAKE_AR:FILEPATH="${compiler_tools["${compiler},llvm_ar"]}" \
			-DCMAKE_BUILD_TYPE:STRING=Debug \
			-DCMAKE_BUILD_WITH_INSTALL_RPATH:BOOL=OFF \
			-DCMAKE_COLOR_DIAGNOSTICS:BOOL=ON \
			-DCMAKE_COLOR_MAKEFILE:BOOL=ON \
			-DCMAKE_CXX_COMPILER:FILEPATH="${compiler_tools["${compiler},clang__"]}" \
			-DCMAKE_CXX_COMPILER_AR:FILEPATH="${compiler_tools["${compiler},llvm_ar"]}" \
			-DCMAKE_CXX_COMPILER_CLANG_SCAN_DEPS:FILEPATH="${compiler_tools["${compiler},clang_scan_deps"]}" \
			-DCMAKE_CXX_COMPILER_LAUNCHER:FILEPATH=/usr/bin/ccache \
			-DCMAKE_CXX_COMPILER_RANLIB:FILEPATH="${compiler_tools["${compiler},llvm_ranlib"]}" \
			-DCMAKE_CXX_FLAGS:STRING='-stdlib++-isystem /usr/lib/gcc/x86_64-pc-linux-gnu/15.2.1/include/c++ -stdlib++-isystem /usr/lib/gcc/x86_64-pc-linux-gnu/15.2.1/include/c++/x86_64-pc-linux-gnu -stdlib++-isystem /usr/lib/gcc/x86_64-pc-linux-gnu/15.2.1/include/c++/backward' \
			-DCMAKE_CXX_FLAGS_DEBUG:STRING='-O0 -ggdb -ggdb3 -g3 -gfull -fno-eliminate-unused-debug-types -fdebug-macro -fno-limit-debug-info -fno-discard-value-names -fno-delete-null-pointer-checks -fforce-dwarf-frame -fkeep-static-consts -fno-optimize-sibling-calls -fno-virtual-function-elimination' \
			-DCMAKE_C_COMPILER:FILEPATH="${compiler_tools["${compiler},clang"]}" \
			-DCMAKE_C_COMPILER_AR:FILEPATH="${compiler_tools["${compiler},llvm_ar"]}" \
			-DCMAKE_C_COMPILER_CLANG_SCAN_DEPS:FILEPATH="${compiler_tools["${compiler},clang_scan_deps"]}" \
			-DCMAKE_C_COMPILER_LAUNCHER:FILEPATH=/usr/bin/ccache \
			-DCMAKE_C_COMPILER_RANLIB:FILEPATH="${compiler_tools["${compiler},llvm_ranlib"]}" \
			-DCMAKE_C_FLAGS_DEBUG:STRING='-O0 -ggdb -ggdb3 -g3 -gfull -fno-eliminate-unused-debug-types -fdebug-macro -fno-limit-debug-info -fno-discard-value-names -fno-delete-null-pointer-checks -fforce-dwarf-frame -fkeep-static-consts -fno-optimize-sibling-calls -fno-virtual-function-elimination' \
			-DCMAKE_DLLTOOL:FILEPATH="${compiler_tools["${compiler},llvm_dlltool"]}" \
			-DCMAKE_ENABLE_ALL_TESTS:BOOL=ON \
			-DCMAKE_EXE_LINKER_FLAGS:STRING="-fuse-ld=${compiler_tools["${compiler},ld_lld"]}" \
			-DCMAKE_EXPORT_COMPILE_COMMANDS:BOOL=ON \
			-DCMAKE_GENERATOR:STRING='Unix Makefiles' \
			-DCMAKE_INSTALL_PREFIX:PATH=/home/swooshy/devstuff/renci/builds/host-qtcreator/clang16-libstdcxx/pfx \
			-DCMAKE_LINKER:FILEPATH="${compiler_tools["${compiler},lld"]}" \
			-DCMAKE_MODULE_LINKER_FLAGS:STRING="-fuse-ld=${compiler_tools["${compiler},ld_lld"]}" \
			-DCMAKE_MT:FILEPATH="${compiler_tools["${compiler},llvm_mt"]}" \
			-DCMAKE_NM:FILEPATH="${compiler_tools["${compiler},llvm_nm"]}" \
			-DCMAKE_OBJCOPY:FILEPATH="${compiler_tools["${compiler},llvm_objcopy"]}" \
			-DCMAKE_OBJDUMP:FILEPATH="${compiler_tools["${compiler},llvm_objdump"]}" \
			-DCMAKE_PREFIX_PATH:PATH=/usr \
			-DCMAKE_RANLIB:FILEPATH="${compiler_tools["${compiler},llvm_ranlib"]}" \
			-DCMAKE_READELF:FILEPATH="${compiler_tools["${compiler},llvm_readelf"]}" \
			-DCMAKE_SHARED_LINKER_FLAGS:STRING="-fuse-ld=${compiler_tools["${compiler},ld_lld"]}" \
			-DCMAKE_STRIP:FILEPATH="${compiler_tools["${compiler},llvm_strip"]}" \
			-DCMAKE_VERBOSE_MAKEFILE:BOOL=ON \
			-DIRODS_BUILD_AGAINST_LIBCXX:BOOL=OFF \
			-DIRODS_BUILD_EXTRA_SHARED_LIBS:BOOL=ON \
			-DIRODS_BUILD_WITH_CLANG:BOOL=ON \
			-DIRODS_BUILD_WITH_WERROR:BOOL=OFF \
			-DIRODS_DIR:PATH=/home/swooshy/devstuff/renci/builds/host-qtcreator/clang16-libstdcxx/pfx/lib/cmake/irods-5.0 \
			-DIRODS_ENABLE_ALL_TESTS:BOOL=ON \
			-DIRODS_EXTERNALS_FULLPATH_BOOST:PATH=/home/swooshy/devstuff/renci/irods-externals-el9-clang16/boost1.81.0-2 \
			-DIRODS_EXTERNALS_FULLPATH_CLANG:PATH="${compiler_dir}" \
			-DIRODS_EXTERNALS_FULLPATH_JSONCONS:PATH=/home/swooshy/devstuff/renci/irods-externals-el9-clang16/jsoncons0.178.0-0 \
			-DIRODS_EXTERNALS_FULLPATH_NANODBC:PATH=/home/swooshy/devstuff/renci/irods-externals-el9-clang16/nanodbc2.13.0-3 \
			-DIRODS_EXTERNALS_FULLPATH_QPID_PROTON:PATH=/home/swooshy/devstuff/renci/irods-externals-el9-clang16/qpid-proton0.36.0-3 \
			-DIRODS_LINUX_DISTRIBUTION_NAME:STRING=arch \
			-DIRODS_LINUX_DISTRIBUTION_VERSION_MAJOR:STRING=none \
			-DIRODS_TEST_EXECUTABLES_BUILD:BOOL=ON \
			-DIRODS_UNIT_TESTS_BUILD:BOOL=ON \
			-DIRODS_UNIT_TESTS_BUILD_WITH_INSTALL_RPATH:BOOL=OFF \
			-DIRODS_UNIT_TESTS_ENABLE_ALL:BOOL=ON \
			-Dfmt_DIR:STRING="/home/swooshy/devstuff/renci/externs/fmt/${fmtver}/usr/lib/cmake/fmt" \
			-Dspdlog_DIR:STRING="/home/swooshy/devstuff/renci/externs/fmt/${fmtver}/usr/lib/cmake/spdlog"

		echo "audit-${build_suffix}:" >> "${builds_dir}/Makefile"
		echo -e "\t"'$(MAKE) '"-C ${builds_dir}/${build_suffix}" >> "${builds_dir}/Makefile"
		echo >> "${builds_dir}/Makefile"

		echo "clean_audit-${build_suffix}:" >> "${builds_dir}/Makefile"
		echo -e "\t"'$(MAKE) clean '"-C ${builds_dir}/${fmtver}" >> "${builds_dir}/Makefile"
		echo >> "${builds_dir}/Makefile"

	done
done

echo -n "clean:" >> "${builds_dir}/Makefile"
for compiler in "${!compilers[@]}"; do
	for fmtver in "${fmtvers[@]}"; do
		build_suffix="${compiler}-fmt${fmtver}"
		echo -n " clean_audit-${build_suffix}" >> "${builds_dir}/Makefile"
	done
done
echo >> "${builds_dir}/Makefile"
echo >> "${builds_dir}/Makefile"

echo -n "all:" >> "${builds_dir}/Makefile"
for compiler in "${!compilers[@]}"; do
	for fmtver in "${fmtvers[@]}"; do
		build_suffix="${compiler}-fmt${fmtver}"
		echo -n " audit-${build_suffix}" >> "${builds_dir}/Makefile"
	done
done
echo >> "${builds_dir}/Makefile"
echo >> "${builds_dir}/Makefile"
cd "${builds_dir}"

make "$@"
