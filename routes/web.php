<?php
use Illuminate\Support\Facades\Route;
/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| contains the "web" middleware group. Now create something great!
|
*/
Route::get('/', function () {
    return view('auth.register');
})->name('register');

Auth::routes();
Route::get('/verify', function () {
    return view('auth.verify');
    
})->name('verify');
Route::post('/verify', [App\Http\Controllers\Auth\RegisterController::class,'verify'])->name('verify');
Route::get('/home', [App\Http\Controllers\HomeController::class, 'index'])->name('home');