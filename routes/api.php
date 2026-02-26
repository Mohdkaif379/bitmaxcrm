<?php

use App\Http\Controllers\Admin\AdminController;
use App\Http\Controllers\Activity\ActivityController;
use App\Http\Controllers\AssignStock\AssignStockController;
use App\Http\Controllers\ChangeAdminCredential\AdminCredentialController;
use App\Http\Controllers\Attendence\AttendenceController;
use App\Http\Controllers\Employee\EmployeeController;
use App\Http\Controllers\Employee\Employee\EmployeeLoginController;
use App\Http\Controllers\Employee\Employee\EmployeeAttendenceController;
use App\Http\Controllers\Employee\Employee\MyProfileController;
use App\Http\Controllers\Employee\Employee\MyTaskController;
use App\Http\Controllers\Expense\ExpenseController;
use App\Http\Controllers\Leads\LeadController;
use App\Http\Controllers\LeadInteraction\LeadInteractionController;
use App\Http\Controllers\Proposal\ProposalController;
use App\Http\Controllers\SalarySlip\SalarySlipController;
use App\Http\Controllers\StockManagement\StockManagementController;
use App\Http\Controllers\SubAdmin\SubAdminController;
use App\Http\Controllers\Task\TaskController;
use App\Http\Controllers\TaskAssign\TaskAssignController;
use App\Http\Controllers\TourConveyance\TourConevyanceFormController;
use App\Http\Controllers\VisitorInvited\VisiterInviteController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::post('admin/login', [AdminController::class, 'login']);
Route::post('admin/logout', [AdminController::class, 'logout']);
Route::get('admins', [AdminController::class, 'index']);
Route::post('admin/create', [AdminController::class, 'store']);
Route::get('admin/profile', [AdminController::class, 'show']);
Route::put('admin/profile', [AdminController::class, 'update']);
Route::delete('admin/profile', [AdminController::class, 'destroy']);
Route::put('admin/password/update', [AdminCredentialController::class, 'updatePassword']);
Route::get('sub-admins', [SubAdminController::class, 'index']);
Route::post('sub-admin/create', [SubAdminController::class, 'store']);
Route::get('sub-admin/{id}', [SubAdminController::class, 'show']);
Route::put('sub-admin/update/{id}', [SubAdminController::class, 'update']);
Route::delete('sub-admin/delete/{id}', [SubAdminController::class, 'destroy']);

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

Route::get('task-assignments', [TaskAssignController::class, 'index']);
Route::post('task-assignment/create', [TaskAssignController::class, 'store']);
Route::get('task-assignment/{id}', [TaskAssignController::class, 'show']);
Route::put('task-assignment/update/{id}', [TaskAssignController::class, 'update']);
Route::delete('task-assignment/delete/{id}', [TaskAssignController::class, 'destroy']);

Route::get('stocks', [StockManagementController::class, 'index']);
Route::post('stock/create', [StockManagementController::class, 'store']);
Route::get('stock/{id}', [StockManagementController::class, 'show']);
Route::put('stock/update/{id}', [StockManagementController::class, 'update']);
Route::delete('stock/delete/{id}', [StockManagementController::class, 'destroy']);

Route::get('assign-stocks', [AssignStockController::class, 'index']);
Route::post('assign-stock/create', [AssignStockController::class, 'store']);
Route::get('assign-stock/{id}', [AssignStockController::class, 'show']);
Route::put('assign-stock/update/{id}', [AssignStockController::class, 'update']);
Route::delete('assign-stock/delete/{id}', [AssignStockController::class, 'destroy']);

Route::get('activities', [ActivityController::class, 'index']);
Route::post('activity/create', [ActivityController::class, 'store']);
Route::get('activity/{id}', [ActivityController::class, 'show']);
Route::put('activity/update/{id}', [ActivityController::class, 'update']);
Route::delete('activity/delete/{id}', [ActivityController::class, 'destroy']);

Route::get('salary-slips', [SalarySlipController::class, 'index']);
Route::post('salary-slip/create', [SalarySlipController::class, 'store']);
Route::get('salary-slip/{id}', [SalarySlipController::class, 'show']);
Route::put('salary-slip/update/{id}', [SalarySlipController::class, 'update']);
Route::delete('salary-slip/delete/{id}', [SalarySlipController::class, 'destroy']);

Route::get('tour-conveyance-forms', [TourConevyanceFormController::class, 'index']);
Route::post('tour-conveyance-form/create', [TourConevyanceFormController::class, 'store']);
Route::get('tour-conveyance-form/{id}', [TourConevyanceFormController::class, 'show']);
Route::put('tour-conveyance-form/update/{id}', [TourConevyanceFormController::class, 'update']);
Route::delete('tour-conveyance-form/delete/{id}', [TourConevyanceFormController::class, 'destroy']);

Route::post('employee/login', [EmployeeLoginController::class, 'login']);
Route::post('employee/logout', [EmployeeLoginController::class, 'logout']);
Route::get('employee/my-profile', [MyProfileController::class, 'show']);
Route::post('employee/my-profile/update', [MyProfileController::class, 'updateMyProfile']);
//Route::put('employee/my-profile/update', [MyProfileController::class, 'updateMyProfile']);
Route::post('employee/attendence/mark-in', [EmployeeAttendenceController::class, 'markIn']);
Route::post('employee/attendence/mark-out', [EmployeeAttendenceController::class, 'markOut']);
Route::post('employee/attendence/break-start', [EmployeeAttendenceController::class, 'breakStart']);
Route::post('employee/attendence/break-end', [EmployeeAttendenceController::class, 'breakEnd']);
Route::get('employee/my-tasks', [MyTaskController::class, 'index']);
Route::put('employee/my-task/status/{taskId}', [MyTaskController::class, 'updateStatus']);
