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
        Schema::create('tour_conveyance_forms', function (Blueprint $table) {
            $table->id();
            $table->string('form_code', 50)->unique();
            $table->string('company_name');
            $table->text('company_address')->nullable();
            $table->string('company_logo_path')->nullable();
            $table->string('form_heading');
            $table->string('form_subheading');
            $table->date('form_date');

            $table->string('employee_name');
            $table->string('employee_id');
            $table->string('designation');
            $table->string('department');
            $table->string('reporting_manager');
            $table->string('cost_center');

            $table->text('purpose');
            $table->string('tour_location');
            $table->string('project_code')->nullable();
            $table->date('tour_from');
            $table->date('tour_to');

            $table->decimal('advance_taken', 12, 2)->default(0.00);
            $table->decimal('total_expense', 12, 2)->default(0.00);
            $table->decimal('balance_payable', 12, 2)->default(0.00);
            $table->decimal('balance_receivable', 12, 2)->default(0.00);

            $table->text('manager_remarks')->nullable();
            $table->string('status')->default('Pending');

            $table->string('footer_heading');
            $table->string('footer_subheading');
            $table->timestamps();

            $table->index('form_date');
            $table->index('employee_id');
            $table->index('status');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('tour_conveyance_forms');
    }
};
