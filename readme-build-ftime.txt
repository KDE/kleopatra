# Analyzing Build Performance

For debug build time:
We need ClangBuildAnalyzer
`
git clone https://github.com/aras-p/ClangBuildAnalyzer
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX=<path> ../
make install
`

## Command line

cmake --preset ftime-trace

ClangBuildAnalyzer --start $PWD/build-ftime-trace
cmake --build --preset ftime-trace

ClangBuildAnalyzer --stop $PWD/build-ftime-trace build-ftime.txt

ClangBuildAnalyzer --analyze build-ftime.txt > analyze-build-ftime.txt


see https://aras-p.info/blog/2019/09/28/Clang-Build-Analyzer/
