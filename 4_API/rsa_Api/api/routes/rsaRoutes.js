'use strict';
module.exports = function(app) {
  var rsa = require('../controllers/rsaController');

  // todoList Routes
  app.route('/tasks')
    .get(rsa.list_all_tasks)
    .post(rsa.create_a_task);


  app.route('/tasks/:taskId')
    .get(rsa.read_a_task)
    .put(rsa.update_a_task)
    .delete(rsa.delete_a_task);
};
