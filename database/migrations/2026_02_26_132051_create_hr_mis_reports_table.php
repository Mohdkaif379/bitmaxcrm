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
        Schema::create('hr_mis_reports', function (Blueprint $table) {
            $table->id();
            $table->string('report_type')->nullable();
            $table->string('department')->nullable();
            $table->date('report_date')->nullable();
            $table->string('report_month')->nullable();
            $table->string('report_year')->nullable();
            $table->string('center_name')->nullable();
            $table->date('week_start_date')->nullable();
            $table->date('week_end_date')->nullable();
            $table->integer('total_employees')->nullable();
            $table->integer('new_hires')->nullable();
            $table->integer('terminations')->nullable();
            $table->integer('resignations')->nullable();
            $table->integer('strength')->nullable();
            $table->integer('total_present')->nullable();
            $table->integer('total_absent')->nullable();
            $table->integer('total_leave')->nullable();
            $table->integer('total_halfday')->nullable();
            $table->integer('total_holiday')->nullable();
            $table->integer('requirement_raised')->nullable();
            $table->integer('position_pending')->nullable();
            $table->integer('position_closed')->nullable();
            $table->integer('interviews_conducted')->nullable();
            $table->integer('selected')->nullable();
            $table->integer('rejected')->nullable();
            $table->enum('process', ['yes', 'no'])->default('no');
            $table->date('salary_disbursement_date')->nullable();
            $table->string('deduction')->nullable();
            $table->text('pending_compliance')->nullable();
            $table->integer('grievance_received')->default(0);
            $table->integer('grievance_resolved')->default(0);
            $table->integer('warning_notice')->default(0);
            $table->integer('appreciation')->default(0);
            $table->integer('training_conducted')->default(0);
            $table->integer('employee_attend')->default(0);
            $table->string('training_feedback')->nullable();
            $table->string('birthday_celebration')->nullable();
            $table->string('engagement_activities')->nullable();
            $table->string('hr_initiatives')->nullable();
            $table->string('special_events')->nullable();
            $table->text('notes')->nullable();
            $table->string('remarks')->nullable();
            $table->unsignedBigInteger('created_by');
            $table->foreign('created_by')->references('id')->on('admins')->onDelete('cascade');
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('hr_mis_reports');
    }
};
