
FetchContent_Declare(cxxopts "Fetching cxxopts..."
  GIT_REPOSITORY
    "https://github.com/jarro2783/cxxopts.git"
  GIT_TAG
    "v3.2.0"
)

FetchContent_MakeAvailable(cxxopts)

add_subdirectory(dumper)
