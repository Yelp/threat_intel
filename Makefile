.DELETE_ON_ERROR:

all:
	echo >&2 "Must specify target."

test:
	tox

clean:
	rm -rf build/ dist/ threat_intel.egg-info/ .tox/
	find . -name '*.pyc' -delete
	find . -name '__pycache__' -delete
.PHONY: all test clean
