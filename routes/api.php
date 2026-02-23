<?php

use App\Http\Controllers\Admin\AdminController;
use App\Http\Controllers\Attendence\AttendenceController;
use App\Http\Controllers\Employee\EmployeeController;
use App\Http\Controllers\Expense\ExpenseController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

// Route::get('/user', function (Request $request) {
//     return $request->user();
// })->middleware('auth:sanctum');

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
