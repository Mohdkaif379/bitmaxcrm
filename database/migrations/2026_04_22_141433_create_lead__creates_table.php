<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('lead_creates', function (Blueprint $table) {
            $table->id();
            $table->string('name')->nullable();
            $table->string('email')->nullable();
            $table->string('phone')->nullable();
            $table->string('company')->nullable();
            $table->string('project_code')->nullable();
            $table->date('date')->nullable();
            $table->text('remarks')->nullable();
            $table->string('project_interested')->nullable();

            $table->string('created_by')->nullable();
            $table->string('status')->default('active');

            $table->string('location')->nullable();

            // attendedBy object
            $table->unsignedBigInteger('attended_by')->nullable();

            $table->foreign('attended_by')
                ->references('id')
                ->on('admins')
                ->nullOnDelete();



            $table->boolean('is_deleted')->default(false);
            $table->timestamp('deleted_at')->nullable();

            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('lead_creates');
    }
};
