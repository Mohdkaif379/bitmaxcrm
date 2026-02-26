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
        Schema::create('evaluation_reports', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('employee_id');
            $table->unsignedBigInteger('created_by')->nullable();
            $table->date('period_to');
            $table->date('period_from');
            $table->date('evaluation_date');
            $table->string('delivery_updates');
            $table->string('quality_standards');
            $table->string('application_performance');
            $table->string('completion_accuracy');
            $table->string('innovation_problems');
            $table->integer('task_efficiency');
            $table->integer('ui_ux_completion');
            $table->integer('debug_testing');
            $table->integer('version_control');
            $table->integer('document_quality');
            $table->text('manager_comments');
            $table->string('collaboration_teamwork');
            $table->string('communicate_reports');
            $table->string('attendence_punctuality');
            $table->integer('professionalism');
            $table->integer('team_collaboration');
            $table->integer('learning_adaptability');
            $table->integer('initiate_ownership');
            $table->integer('team_management');
            $table->text('hr_comments');
            $table->integer('skills');
            $table->integer('task_delivery');
            $table->integer('quality_work');
            $table->integer('communication');
            $table->integer('behaviour_teamwork');
            $table->string('performance_grade');
            $table->text('final_feedback');
            $table->foreign('employee_id')->references('id')->on('employees')->onDelete('cascade');
            $table->foreign('created_by')->references('id')->on('admins')->onDelete('set null');
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('evaluation_reports');
    }
};
