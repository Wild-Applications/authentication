var moment = require('moment');

var time = {};

time.isWithinHours = function(dateToTest, numOfHours){
  return moment().diff(moment(dateToTest), 'hours') < numOfHours;
}

module.exports = time;
//tests
