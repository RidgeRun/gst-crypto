SUBDIRS = src

EXTRA_DIST = autogen.sh


# Clear dependency_libs for multiarch
all-local:
	sed -i "/dependency_libs/ s/'.*'/''/" `find . -name '*.la'`
	sed -i "/dependency_libs/ s/'.*'/''/" `find . -name '*.lai'`

