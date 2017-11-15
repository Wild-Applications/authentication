var moment = require('moment');

var time = {};

time.isWithinHours = function(dateToTest, numOfHours){
  return moment(dateToTest).diff(moment(), 'hours') < numOfHours;
}

module.exports = time;
