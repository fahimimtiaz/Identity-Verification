import React, { useState, useEffect } from 'react';

const TaskForm = ({ onSubmit, initialData }) => {
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [dueDate, setDueDate] = useState('');
  const [priority, setPriority] = useState('Medium');
  const [status, setStatus] = useState('ToDo');


  useEffect(() => {
    if (initialData) {
      setTitle(initialData.title);
      setDescription(initialData.description);
      setDueDate(initialData.due_date);
      setPriority(initialData.priority);
      setStatus(initialData.status || 'ToDo');
    }
  }, [initialData]);

  const handleSubmit = (e) => {
    e.preventDefault();
    onSubmit({ task_id: initialData?.task_id,
      title, description, due_date: dueDate, priority, status });
  };

  return (
    <form onSubmit={handleSubmit}
      className='max-w-md mx-auto bg-white shadow-md rounded px-8 pt-6 pb-8 mb-4 mt-6'
    >
      <h2 className="text-2xl font-bold leading-tight text-black text-center">
        Create Tasks
      </h2>

      <label className="form-control w-full ">
        <div className="label">
          <span className="label-text">Title</span>
        </div>
        <input
          type="text"
          placeholder="Enter task title"
          className="input input-bordered w-full "
          value={title}
          onChange={(e) => setTitle(e.target.value)}
          required
        />
      </label>

      <label className="form-control">
        <div className="label">
          <span className="label-text">Description</span>
        </div>
        <textarea
          className="textarea textarea-bordered h-24"
          placeholder="Enter task description"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          required
        />
      </label>

      <label className="form-control w-full ">
        <div className="label">
          <span className="label-text">Due Date</span>
        </div>
        <input
          type="date"
          className="input input-bordered w-full "
          value={dueDate}
          onChange={(e) => setDueDate(e.target.value)}
          required
        />
      </label>

      <label className="form-control w-full ">
        <div className="label">
          <span className="label-text">Priority</span>
        </div>
        <select
          className="select select-bordered"
          value={priority}
          onChange={(e) => setPriority(e.target.value)}
          required
        >
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>
      </label>

      <div className="form-control w-full">

        <div className="label">
          <span className="label-text">Status</span>
        </div>
        <select
          className="select select-bordered"
          value={status}
          onChange={(e) => setStatus(e.target.value)}
          required
        >
          <option value="ToDo">To Do</option>
          {/* <option value="InProgress">In Progress</option> */}
          <option value="Done">Done</option>
        </select>
      </div>

      <div>
        <button
          type="submit"
          className="inline-flex w-full items-center justify-center rounded-md bg-black px-3.5 py-2.5 mt-6 font-semibold leading-7 text-white hover:bg-black/80"
        >
          {initialData ? 'Update Task' : 'Create Task'}
        </button>
      </div>
    </form>
  );
};

export default TaskForm;
