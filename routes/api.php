<?php

use App\Http\Controllers\Admin\AdminController;
use App\Http\Controllers\Attendence\AttendenceController;
use App\Http\Controllers\Employee\EmployeeController;
use App\Http\Controllers\Expense\ExpenseController;
use App\Http\Controllers\Leads\LeadController;
use App\Http\Controllers\LeadInteraction\LeadInteractionController;
use App\Http\Controllers\Proposal\ProposalController;
use App\Http\Controllers\Task\TaskController;
use App\Http\Controllers\VisitorInvited\VisiterInviteController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::post('admin/login', [AdminController::class, 'login']);
Route::post('admin/logout', [AdminController::class, 'logout']);
Route::get('admins', [AdminController::class, 'index']);
Route::post('admin/create', [AdminController::class, 'store']);
// Route::get('admins/{id}', [AdminController::class, 'show']);
Route::put('admin/profile', [AdminController::class, 'update']);
Route::delete('admin/profile', [AdminController::class, 'destroy']);

Route::get('employees', [EmployeeController::class, 'index']);
Route::post('employee/create', [EmployeeController::class, 'store']);
Route::get('employees/{id}', [EmployeeController::class, 'show']);
Route::put('employee/update/{id}', [EmployeeController::class, 'update']);
Route::delete('employee/delete/{id}', [EmployeeController::class, 'destroy']);

Route::post('attendence/mark-in', [AttendenceController::class, 'markIn']);
Route::post('attendence/mark-out', [AttendenceController::class, 'markOut']);
Route::post('attendence/break-start', [AttendenceController::class, 'breakStart']);
Route::post('attendence/break-end', [AttendenceController::class, 'breakEnd']);
Route::get('attendence/all', [AttendenceController::class, 'index']);
Route::get('attendence/employee/{employeeId}', [AttendenceController::class, 'showByEmployee']);
Route::put('attendence/update/{id}', [AttendenceController::class, 'update']);
Route::delete('attendence/delete/{id}', [AttendenceController::class, 'destroy']);

Route::get('expenses', [ExpenseController::class, 'index']);
Route::post('expense/create', [ExpenseController::class, 'store']);
Route::get('expense/{id}', [ExpenseController::class, 'show']);
Route::put('expense/update/{id}', [ExpenseController::class, 'update']);
Route::delete('expense/delete/{id}', [ExpenseController::class, 'destroy']);

Route::get('visitor-invites', [VisiterInviteController::class, 'index']);
Route::post('visitor-invite/create', [VisiterInviteController::class, 'store']);
Route::get('visitor-invite/{id}', [VisiterInviteController::class, 'show']);
Route::put('visitor-invite/update/{id}', [VisiterInviteController::class, 'update']);
Route::delete('visitor-invite/delete/{id}', [VisiterInviteController::class, 'destroy']);

Route::get('leads', [LeadController::class, 'index']);
Route::post('lead/create', [LeadController::class, 'store']);
Route::get('lead/{id}', [LeadController::class, 'show']);
Route::put('lead/update/{id}', [LeadController::class, 'update']);
Route::delete('lead/delete/{id}', [LeadController::class, 'destroy']);

Route::get('lead-interactions', [LeadInteractionController::class, 'index']);
Route::post('lead-interaction/create', [LeadInteractionController::class, 'store']);
Route::get('lead-interaction/{id}', [LeadInteractionController::class, 'show']);
Route::put('lead-interaction/update/{id}', [LeadInteractionController::class, 'update']);
Route::delete('lead-interaction/delete/{id}', [LeadInteractionController::class, 'destroy']);

Route::get('proposals', [ProposalController::class, 'index']);
Route::post('proposal/create', [ProposalController::class, 'store']);
Route::get('proposal/{id}', [ProposalController::class, 'show']);
Route::put('proposal/update/{id}', [ProposalController::class, 'update']);
Route::delete('proposal/delete/{id}', [ProposalController::class, 'destroy']);

Route::get('tasks', [TaskController::class, 'index']);
Route::post('task/create', [TaskController::class, 'store']);
Route::get('task/{id}', [TaskController::class, 'show']);
Route::put('task/update/{id}', [TaskController::class, 'update']);
Route::delete('task/delete/{id}', [TaskController::class, 'destroy']);
