const { pathsToModuleNameMapper } = require('ts-jest');
const { compilerOptions } = require('./apps/tsconfig.base.json');

module.exports = {
  moduleNameMapper: pathsToModuleNameMapper(compilerOptions.paths || {}, {
    prefix: '<rootDir>/../',
  }),
};
