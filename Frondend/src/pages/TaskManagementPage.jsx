import React, { useState, useEffect } from 'react';
import TaskForm from '../component/TaskForm';
import TaskList from '../component/TaskList';
import { getTasks, createTask, updateTask, deleteTask } from '../services/api';
import { getToken } from '../services/auth';
import './styles.css';
import Navbar from '../component/Navbar';


const TaskManagementPage = () => {
  const [tasks, setTasks] = useState({ High: [], Medium: [], Low: [] });
  const [editingTask, setEditingTask] = useState(null);
  const [taskToDelete, setTaskToDelete] = useState(null);
  const [verificationStatus, setVerificationStatus] = useState(null);

  useEffect(() => {
    const userData = localStorage.getItem('userData');
    const parsedUserData = userData ? JSON.parse(userData) : null;
    setVerificationStatus(parsedUserData?.verification_status);

    if (parsedUserData?.verification_status === 'Verified') {
      const fetchTasks = async () => {
        try {
          const token = getToken();
          const response = await getTasks(token);
          const fetchedTasks = response.data.data || { High: [], Medium: [], Low: [] };
          console.log('Fetched Tasks:', fetchedTasks);
          setTasks(fetchedTasks);
        } catch (error) {
          console.error('Error fetching tasks:', error);
        }
      };

      fetchTasks();
    }
  }, []);

  const handleCreate = async (taskData) => {
    console.log(taskData);
    try {
      const token = getToken();
      const response = await createTask(taskData, token);
      if (response.status === 200) {
        setTasks((prevTasks) => ({
          ...prevTasks,
          [taskData.priority]: [...prevTasks[taskData.priority], taskData],
        }));
        window.location.reload();
      }
    } catch (error) {
      console.error('Error creating task:', error);
    }
  };

  const handleUpdate = async (taskData) => {
    try {
      const token = getToken();
      await updateTask(taskData, token);
      setTasks((prevTasks) => {
        const updatedTasks = { ...prevTasks };
        const priorityTasks = updatedTasks[taskData.priority];
        const taskIndex = priorityTasks.findIndex((task) => task.task_id === taskData.task_id);
        if (taskIndex !== -1) {
          priorityTasks[taskIndex] = taskData;
        }
        return updatedTasks;
      });
      setEditingTask(null);
      document.getElementById('edit-modal').close();
    } catch (error) {
      console.error('Error updating task:', error.message);
      alert(`Failed to update task: ${error.message}`);
    }
  };

  const handleDelete = async () => {
    try {
      const token = getToken();
      await deleteTask(taskToDelete.task_id, token);
      setTasks((prevTasks) => ({
        ...prevTasks,
        [taskToDelete.priority]: prevTasks[taskToDelete.priority].filter((task) => task.task_id !== taskToDelete.task_id),
      }));
      setTaskToDelete(null);
      document.getElementById('delete-modal').close();
    } catch (error) {
      console.error('Error deleting task:', error);
    }
  };

  if (verificationStatus !== 'Verified') {
    return(
    <>
      <Navbar  />
      <div>Your account must be verified to manage tasks.</div>
    </>
    );
  }

  return (
    <>
    <Navbar  />
    <div className="form-container">
        <h1 className="text-4xl font-bold leading-tight text-black text-center">Task Management</h1>
        <div className="task-form-container">
        <TaskForm onSubmit={editingTask ? handleUpdate : handleCreate} initialData={editingTask} />
      </div>
      
      <div className="task-list-container 
          max-w-4xl mx-auto bg-white shadow-md rounded px-8 pt-6 pb-8 mb-4">
        {Object.keys(tasks).map((priority) => (
          <div key={priority}>
            <h2 className="text-xl font-semibold leading-tight text-black mt-10 mb-4">{priority} Priority Tasks</h2>
            <TaskList
              tasks={tasks[priority]}
              onEdit={(task) => { setEditingTask(task); document.getElementById('edit-modal').showModal(); }}
              onDelete={(task) => { setTaskToDelete(task); document.getElementById('delete-modal').showModal(); }}
            />
          </div>
        ))}
      </div>

      {/* Edit Modal */}
      <dialog id="edit-modal" className="modal modal-bottom sm:modal-middle">
        <div className="modal-box">
          <h3 className="font-bold text-lg">Edit Task</h3>
          <TaskForm onSubmit={handleUpdate} initialData={editingTask} />
          <div className="modal-action">
            <button className="btn" onClick={() => document.getElementById('edit-modal').close()}>Close</button>
          </div>
        </div>
      </dialog>

      {/* Delete Modal */}
      <dialog id="delete-modal" className="modal modal-bottom sm:modal-middle">
        <div className="modal-box">
          <h3 className="font-bold text-lg">Confirm Deletion</h3>
          <p className="py-4">Are you sure you want to delete this task?</p>
          <div className="modal-action">
            <button className="btn btn-danger" onClick={handleDelete}>Delete</button>
            <button className="btn" onClick={() => document.getElementById('delete-modal').close()}>Cancel</button>
          </div>
        </div>
      </dialog>
    </div>
    </>
  );
};

export default TaskManagementPage;
