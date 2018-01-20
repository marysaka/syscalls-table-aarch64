#!/bin/bash

KERNEL_VERSION="4.14.14"

# Force install ctags because we are missing things otherwise...
pushd node_modules/ctags
npm install
popd

node generate_table.js ${KERNEL_VERSION} && node ./generate_html.js > docs/latest.html