<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\DB;

class LeadCreateSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        DB::statement('SET FOREIGN_KEY_CHECKS=0;');
        DB::table('lead_creates')->truncate();

        $data = [
            [1,'Rahul Sharma','rahul@example.com','9876543210','BitMax Pvt Ltd','PRJ-1001','2026-04-22','Interested in premium plan','CRM Suite','deleted','Kolkata',1,1,'2026-04-22 15:06:34','2026-04-22 15:05:07','2026-04-22 15:06:34'],
            [2,'KAIFSharmaaaaaa','rahulkaif.new@example.com','9876243210','BitMax Pvt Ltd','PRJ-1001','2026-04-21','Follow-up done','CRM Suite','deleted','Kolkata',1,1,'2026-04-22 15:52:40','2026-04-22 15:07:46','2026-04-22 15:52:40'],
            [3,'werty','super@erp.com','1234567890','wertyu','wertyui','2026-04-22','ertyui','ertyui','deleted','qwertyui',1,1,'2026-04-22 15:52:05','2026-04-22 15:51:59','2026-04-22 15:52:05'],
            [4,'Jitendra Kumar Patel','jitendrasingh77384@gmail.com','7470903022','Bpo Chat Process',NULL,'2026-04-22','Sent Project details',NULL,'deleted','Rewa, Madhya Pradesh',1,1,'2026-04-22 15:55:17','2026-04-22 15:54:54','2026-04-22 15:55:17'],
            [5,'Jitendra Kumar Patel','jitendrasingh77384@gmail.com','7470903022','Bpo Chat Process',NULL,'2026-04-22','Sent Project details',NULL,'active','Rewa, Madhya Pradesh',1,0,NULL,'2026-04-22 15:55:32','2026-04-22 15:55:32'],
            [6,'Thippagudisa Dayakar Babu','dayakarbabu1997@gmail.com','9177858766','Bpo Chat Process',NULL,'2026-04-22','Sent Project details',NULL,'active','Bangalore',1,0,NULL,'2026-04-22 15:55:55','2026-04-22 15:55:55'],
            [7,'Muzamil','muzamil.a1998@gmail.com','7975934071','Bpo Chat Process',NULL,'2026-04-22','Sent Project details',NULL,'active','Bangalore',1,0,NULL,'2026-04-22 15:56:18','2026-04-22 15:56:18'],
            [8,'Santosh','kanidhancommunications@gmail.com','7418942054','Bpo Chat Process',NULL,'2026-04-22','Sent Project details',NULL,'active','Hosur, Tamilnadu',1,0,NULL,'2026-04-22 16:07:50','2026-04-22 16:07:50'],
            [9,'Azagar Ali Shaik','azagarlishaik@aalitech.com','8143265445','Bpo Chat Process',NULL,'2026-04-22','Sent Project details',NULL,'active','Guntur, Andhra Pradesh',1,0,NULL,'2026-04-22 16:07:59','2026-04-22 16:07:59'],
            [10,'Jagadish','jagadish@roxonn.com','8886157111','Bpo Chat Process',NULL,'2026-04-22','Sent Project details',NULL,'active','Uttar Pradesh',1,0,NULL,'2026-04-22 16:08:11','2026-04-22 16:08:11'],
            [11,'Salman','salmansharieff77@gmail.com','8884483163','Bpo Chat Process',NULL,'2026-04-22','Sent Project details',NULL,'active','Bangalore',1,0,NULL,'2026-04-22 16:08:23','2026-04-22 16:08:23'],
            [12,'Elakkiya','uelakkiya98@gmail.com','9940539711','Bpo Chat Process',NULL,'2026-04-22','Sent Project details',NULL,'active','Chennai, Tamilnadu',1,0,NULL,'2026-04-22 16:08:31','2026-04-22 16:08:31'],
            [13,'Samarth','samarthjairaj24@gmail.com','9515783300','Bpo Chat Process',NULL,'2026-04-17','Sent Project Details',NULL,'active','Bhopal MP',1,0,NULL,'2026-04-22 16:11:41','2026-04-22 16:11:41'],
            [14,'Umesh Patil','dggateway2@gmail.com','8600067272','Bpo Chat Process',NULL,'2026-04-17','Sent Project Details',NULL,'active','Pune Maharashtra',1,0,NULL,'2026-04-22 16:11:53','2026-04-22 16:11:53'],
            [15,'Ajay Parmar','apajay4482@gmail.com','9993076099','Bpo Chat Process',NULL,'2026-04-17','Sent Project Details',NULL,'active','Dewes, Madhya Pradesh',1,0,NULL,'2026-04-22 16:12:01','2026-04-22 16:12:01'],
            [16,'Niyati Dayalkar','niyatidhayalkar10@gmail.com','8879271928','Bpo Chat Process',NULL,'2026-04-17','Sent Project Details',NULL,'active','Dombivli East Mumbai',1,0,NULL,'2026-04-22 16:12:11','2026-04-22 16:12:11'],
            [17,'Niyati Dayalkar','niyatidhayalkar10@gmail.com','8879271928','Bpo Chat Process',NULL,'2026-04-17','Sent Project Details',NULL,'deleted','Dombivli East Mumbai',1,1,'2026-04-22 16:15:52','2026-04-22 16:12:26','2026-04-22 16:15:52'],
            [18,'Mallikarjun','k.malli571@gmail.com','9441910913','Bpo Chat Process',NULL,'2026-04-17','Sent Project Details',NULL,'active','Secada Hyderabad',1,0,NULL,'2026-04-22 16:12:34','2026-04-22 16:12:34'],
            [19,'Omkar Sonkusare','omkarsonkusare05@gmail.com','9552239161','Bpo Chat Process',NULL,'2026-04-17','Sent Project Details',NULL,'active','Nagpur Maharastra',1,0,NULL,'2026-04-22 16:12:49','2026-04-22 16:12:49'],
            [20,'Ansari Hussain','ha5809435@gmail.com','9920331420','Bpo Chat Process',NULL,'2026-04-17','Sent Project Details',NULL,'active','Thane Mumbai',1,0,NULL,'2026-04-22 16:13:39','2026-04-22 16:13:39'],
            [21,'Joseph jude Vinard R.','joseph@dreamhunterz.com','9367699846','Bpo Chat Process',NULL,'2026-04-17','Sent Project Details',NULL,'active','Hosur Tamilnadu',1,0,NULL,'2026-04-22 16:13:47','2026-04-22 16:13:47'],
            [22,'Palak Sharma','palak26sharma123@gmail.com','6264390892','Bpo Chat Process',NULL,'2026-04-17','Sent Project details',NULL,'active','Indore, MP',1,0,NULL,'2026-04-22 16:13:55','2026-04-22 16:13:55'],
            [23,'Mahantesh Pyati','mahanteshpyatib@gmail.com','7406614207','Bpo Chat Process',NULL,'2026-04-17','Sent Project details',NULL,'active','Bangalore',1,0,NULL,'2026-04-22 16:14:53','2026-04-22 16:14:53'],
            [24,'Atul Girhepunje','atul3@yahoo.com3','7972053727','Bpo Chat Process','Not Decided Yet','2026-04-22','Sent Project details','Bpo Chat Process','deleted','Gondia, Maharastra',1,1,'2026-04-22 18:23:46','2026-04-22 17:45:31','2026-04-22 18:23:46'],
            [25,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,'deleted',NULL,1,1,'2026-04-22 17:46:20','2026-04-22 17:45:51','2026-04-22 17:46:20'],
            [26,'Sandhya Parthiban','aathmikaparthiban@gmail.com','9962074415','Bpo Chat Process','Not Decided Yet','2026-04-22','Sent Project details','Bpo Chat Process','active','Thiruvallur',1,0,NULL,'2026-04-22 17:47:39','2026-04-22 17:47:39'],
            [27,'Sunil G.','contact@genemaxit.com','9663858109','Bpo Chat Process','Not Decided Yet','2026-04-22','Sent Project details','Bpo Chat Process','active','Bangalore',1,0,NULL,'2026-04-22 17:48:07','2026-04-22 17:48:07'],
            [28,'Mohan Kandhaiya','mohankandhaiya98@gmail.com','9677992240','Bpo Chat Process','Not Decided Yet','2026-04-22','Sent Project details','Bpo Chat Process','active','MGP Palace Erode',1,0,NULL,'2026-04-22 17:48:33','2026-04-22 17:48:33'],
            [29,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,'deleted',NULL,1,1,'2026-04-22 18:21:03','2026-04-22 18:17:43','2026-04-22 18:21:03'],
            [30,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,'deleted',NULL,1,1,'2026-04-22 18:21:44','2026-04-22 18:21:11','2026-04-22 18:21:44'],
            [31,'D. Balaji','ceo@ematixsolutions.com','8838856132','Bpo Chat Process','Not Decided Yet','2026-04-22','Sent Project details','Bpo Chat Process','active','Salem, Tamilnadu',1,0,NULL,'2026-04-22 18:21:33','2026-04-22 18:21:33'],
            [32,'Bachendri Pal','raon88247@gmail.com','6394915070','Bpo Chat Process','Not Decided Yet','2026-04-22','Sent Project details','Bpo Chat Process','active','Bangalore',1,0,NULL,'2026-04-22 18:23:10','2026-04-22 18:23:10'],
            [33,'Atul Girhepunje','atul3@yahoo.com3','7972053727','Bpo Chat Process','Not Decided Yet','2026-04-22','Sent Project details','Bpo Chat Process','active','Gondia, Maharastra',1,0,NULL,'2026-04-22 18:23:36','2026-04-22 18:23:36'],
            [34,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,'deleted',NULL,1,1,'2026-04-22 18:31:06','2026-04-22 18:30:48','2026-04-22 18:31:06'],
            [35,'Shaik Suhel Basha','ssbcareerconsultants@gmail.com','7893193160','Bpo Chat Process','Not Decided Yet','2026-04-22','Sent Project details','Bpo Chat Process','active','Hindupur, Andhra Pradesh',1,0,NULL,'2026-04-22 18:31:11','2026-04-22 18:31:11'],
            [36,'Udit Kesarwani','uditkesari999@gmail.com','7823727239','Bpo Chat Process','Not Decided Yet','2026-04-24','Done','Bpo Chat Process','deleted','Noida',1,1,'2026-04-24 16:26:14','2026-04-24 16:25:31','2026-04-24 16:26:14'],
            [37,'Udit Kesarwaniiii','uditkesari999@gmail.com','7823727239','UCompany','Not Decided Yet','2026-04-25','12e12e','Bpo Chat Process','deleted','Noida',1,1,'2026-04-25 11:07:02','2026-04-25 11:06:50','2026-04-25 11:07:02'],
            [38,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,'deleted',NULL,1,1,'2026-05-07 16:57:46','2026-05-07 16:57:35','2026-05-07 16:57:46'],
            [39,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,'deleted',NULL,1,1,'2026-05-07 17:01:30','2026-05-07 17:01:16','2026-05-07 17:01:30'],
            [40,'Ashish Kashyap','ash.kashyap2710@gmail.com','7982447213','Bpo Chat Process','Not Decided Yet',NULL,'Sent Project details','Bpo Chat Process','active','Gurgaon',1,0,NULL,'2026-05-07 17:01:43','2026-05-07 17:01:43'],
            [41,'Himanshu Vasistha','vasistha416@gmail.com','8826024564','Bpo Chat Process','Not Decided Yet',NULL,'Sent Project details','Bpo Chat Process','active','Shamli UP',1,0,NULL,'2026-05-07 17:01:55','2026-05-07 17:01:55'],
            [42,'Srikanth','srikanthzion@gmail.com','9493467024','Bpo Chat Process','Not Decided Yet',NULL,'Sent Project details','Bpo Chat Process','active','Telangana',1,0,NULL,'2026-05-07 17:02:06','2026-05-07 17:02:06'],
            [43,'Nirmal Singh','nirmalren13@gmail.com','8015882113','Bpo Chat Process','Not Decided Yet',NULL,'Sent Project details','Bpo Chat Process','active','Pondicherry',1,0,NULL,'2026-05-07 17:02:15','2026-05-07 17:02:15'],
            [44,'Shubh Upadhayay','shubhupadhaya6@gmail.com','8790864837','Bpo Chat Process','Not Decided Yet',NULL,'Sent Project details','Bpo Chat Process','active','Tamilnadu',1,0,NULL,'2026-05-07 17:02:29','2026-05-07 17:02:29'],
            [45,'Sam Krishnan','kanidhancompany@gmail.com','7904373361','Bpo Chat Process','Not Decided Yet',NULL,'Sent Project details','Bpo Chat Process','active','Tamilnadu',1,0,NULL,'2026-05-07 17:02:38','2026-05-07 17:02:38'],
            [46,'Raj','velpula1610@gmail.com','9390286580','Bpo Chat Process','Not Decided Yet',NULL,'Sent Proejct details','Bpo Chat Process','active','Indore, MP',1,0,NULL,'2026-05-07 17:02:46','2026-05-07 17:02:46'],
            [47,'Manohar','davidmanohar007@gmail.com','9705016367','Bpo Chat Process','Not Decided Yet',NULL,'Sent Project details','Bpo Chat Process','active','Hyderanbad',1,0,NULL,'2026-05-07 17:02:55','2026-05-07 17:02:55'],
            [48,'Akash Ahuja','akashahujaelevan@gmail.com','8398989915','Bpo Chat Process','Not Decided Yet',NULL,'Sent Project details','Bpo Chat Process','active','Delhi',1,0,NULL,'2026-05-07 17:03:03','2026-05-07 17:03:03'],
            [49,'Arindam Sen','arindamsen824@gmail.com','9531670654','Bpo Chat Process','Not Decided Yet',NULL,'Sent Project details','Bpo Chat Process','active','Durgapur West Bengal',1,0,NULL,'2026-05-07 17:03:12','2026-05-07 17:03:12'],
            [50,'Kallesh NC','kalleshnc95@gmail.com','9900524916','Bpo Chat Process','Not Decided Yet',NULL,'Can\'t afford now......Sent Project details','Bpo Chat Process','inactive','Bangalore, Karnataka',1,0,NULL,'2026-05-07 17:03:20','2026-05-07 17:03:20'],
            [51,'Shakti Singh Bhati','shaktisinghbhati2002@gmail.com','9929529744','Bpo Chat Process','Not Decided Yet',NULL,'Sent Project details','Bpo Chat Process','active','Udaipur, Rajasthan',1,0,NULL,'2026-05-07 17:03:29','2026-05-07 17:03:29'],
            [52,'Bogguru kumar Reddy','reddykuber5@gmail.com','7032793089','Bpo Chat Process','Not Decided Yet',NULL,'Sent Project details','Bpo Chat Process','active','Kurnool, Andhra Pradesh',1,0,NULL,'2026-05-07 17:03:37','2026-05-07 17:03:37'],
            [53,'Chirag Gohil','chiraggohil1114@gmail.com','7415367639','Bpo Chat Process','Not Decided Yet',NULL,'Sent Project details','Bpo Chat Process','active','Bhopal, MP',1,0,NULL,'2026-05-07 17:03:45','2026-05-07 17:03:45'],
            [54,'Syed Kaif Ali','digitalkaifu@gmail.com','8218043967','Bpo Chat Process','Not Decided Yet',NULL,'Sent Project details','Bpo Chat Process','active','Agra UP',1,0,NULL,'2026-05-07 17:03:53','2026-05-07 17:03:53'],
            [55,'Satwinder Singh','satwinder.singh@lingo.com','6239149488','Bpo Chat Process','Not Decided Yet',NULL,'Sent Project Details','Bpo Chat Process','active','Chandigarh',1,0,NULL,'2026-05-07 17:04:01','2026-05-07 17:04:01'],
            [56,'Manish','kumarmanish1998.hcst@gmail.com','9667697519','Bpo Chat Process','Not Decided Yet',NULL,'Sent Project Details','Bpo Chat Process','active','Agra, UP',1,0,NULL,'2026-05-07 17:04:10','2026-05-07 17:04:10'],
            [57,'Krishna Jha','service@ashentrix.com','9508419308','Bpo Chat Process','Not Decided Yet',NULL,'Sent Project Details','Bpo Chat Process','active','Noida',1,0,NULL,'2026-05-07 17:04:18','2026-05-07 17:04:18'],
            [58,'Rachit Tiwari','rachittiwarishawan@gmail.com','7380904074','Bpo Chat Process','Not Decided Yet',NULL,'Sent Project details','Bpo Chat Process','active','Varansi, UP',1,0,NULL,'2026-05-07 17:04:25','2026-05-07 17:04:25'],
            [59,'Arnish Kumar Adhessh','resurai27@gmail.com','8307679096','Bpo Chat Process','Not Decided Yet',NULL,'Sent Project details','Bpo Chat Process','active','Lucknow UP',1,0,NULL,'2026-05-07 17:04:35','2026-05-07 17:04:35'],
            [60,'Samiit Kumar Patra','samit.patra@yahoo.com','9831522456','Bpo Chat Process','Not Decided Yet',NULL,'Sent Project details','Bpo Chat Process','active','Kolkata',1,0,NULL,'2026-05-07 17:04:44','2026-05-07 17:04:44'],
            [61,'R. manjunath','manjunathdhfm@gmail.com','7997520901','Bpo Chat Process','Not Decided Yet',NULL,'Sent Project details','Bpo Chat Process','active','Hindupur',1,0,NULL,'2026-05-07 17:04:51','2026-05-07 17:04:51'],
            [62,'Mayank','mayankhijain@gmail.com','9924087904','Bpo Chat Process','Not Decided Yet',NULL,'Sent Project details','Bpo Chat Process','active','Ahmedabad Gujrat',1,0,NULL,'2026-05-07 17:04:59','2026-05-07 17:04:59'],
            [63,'Sunil','tssgroupimphal@gmail.com','9366132542','Bpo Chat Process','Not Decided Yet',NULL,'Sent Project details','Bpo Chat Process','active','Manipur',1,0,NULL,'2026-05-07 17:05:07','2026-05-07 17:05:07'],
            [64,'Jammu','alcjammu@gmail.com','9419105383','Bpo Chat Process','Not Decided Yet',NULL,'Sent Project details','Bpo Chat Process','active','J&K',1,0,NULL,'2026-05-07 17:05:17','2026-05-07 17:05:17'],
            [65,'Naveen Sharma','naveensharma8192@gmail.com','8839593844','Bpo Chat Process','Not Decided Yet',NULL,'Sent Project details','Bpo Chat Process','active','Shivpuri MP',1,0,NULL,'2026-05-07 17:05:25','2026-05-07 17:05:25'],
            [66,'Rahul','chavdrahul1919@gmail.com','8056965236','Bpo Chat Process','Not Decided Yet',NULL,'Sent Project details','Bpo Chat Process','active','Gujarat',1,0,NULL,'2026-05-07 17:05:33','2026-05-07 17:05:33'],
            [67,'Abhishek','chilluabhishek@gmail.com','8056965236','Bpo Chat Process','Not Decided Yet',NULL,'Sent Project details.','Bpo Chat Process','active','Tenkari, Tamilnadu',1,0,NULL,'2026-05-07 17:05:41','2026-05-07 17:05:41'],
            [68,'Manish Manjhi','manjhimanish97@gmail.com','9009957892','Bpo Chat Process','Not Decided Yet',NULL,'Sent Project details.','Bpo Chat Process','active','Gwalior, MP',1,0,NULL,'2026-05-07 17:05:50','2026-05-07 17:05:50'],
            [69,'Ganesh','ganeshpandavula7883@gmail.com','9640256305','Bpo Chat Process','Not Decided Yet',NULL,'Sent Project details.','Bpo Chat Process','active','Hyderabad',1,0,NULL,'2026-05-07 17:05:57','2026-05-07 17:05:57'],
            [70,'Aditya Kumar','adityaglobalpike@gmail.com','7277038578','Bpo Chat Process','Not Decided Yet',NULL,'Sent Project details.','Bpo Chat Process','active','Patna, Bihar',1,0,NULL,'2026-05-07 17:06:05','2026-05-07 17:06:05'],
            [71,'Pratik Ashok Bhuyarkar','pratikbhuyarkar@gmail.com','9284177897','Bpo Chat Process','Not Decided Yet',NULL,'Sent Project details.','Bpo Chat Process','active','Nagpur Maharastra',1,0,NULL,'2026-05-07 17:06:17','2026-05-07 17:06:17'],
            [72,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,'deleted',NULL,1,1,'2026-05-07 17:06:43','2026-05-07 17:06:25','2026-05-07 17:06:43'],
            [73,'Karan Gupta','karangupta47440@gmail.com','7719631369','Bpo Chat Process','Not Decided Yet',NULL,'Sent Project details.','Bpo Chat Process','inactive','Amritsar Punjab',1,0,NULL,'2026-05-07 17:06:49','2026-05-07 17:06:49'],
            [74,'Rishabh Dubey','drishabh850@gmail.com','7992072380','Bpo Chat Process','Not Decided Yet',NULL,'Sent Project details.','Bpo Chat Process','active','Kanpur Up',1,0,NULL,'2026-05-07 17:06:56','2026-05-07 17:06:56'],
            [75,'Raynold Victor','victorrayno2@gmail.com','920259753',NULL,'Not decided yet','2026-05-11','Sent project details','BPO Chat Process','active','Indore MP',14,0,NULL,'2026-05-11 14:40:22','2026-05-11 14:40:22'],
            [76,'Santosh','teleconnectbs@gmail.com','7208497971','Teleconnect Business solution','Not decided yet','2026-05-11','Sent Project details','BPO Chat Process','active','Mumbai',14,0,NULL,'2026-05-11 14:42:09','2026-05-11 14:42:09'],
            [77,'Siddik','siddikb@gmail.com','9619826411  971559553824','Data Sync IT Solutions','Not decided yet','2026-05-11','Sent Project details','BPO Chat Process','active','Navi Mumbai',14,0,NULL,'2026-05-11 14:43:52','2026-05-11 14:43:52'],
            [78,'Louis','digitalmedia6699@gmail.com','8406084060','Louis Enterprises','Not decided yet','2026-05-11','Sent Project details','BPO Chat Process','active','Andhra Pradesh',14,0,NULL,'2026-05-11 14:46:00','2026-05-11 14:46:00'],
            [79,'Sanjay','sanjayt25@gmail.com','9925943391',NULL,'Not decided yet','2026-05-11','Sent Project details','BPO Chat Process','active','Ahmedabad Gujrat',14,0,NULL,'2026-05-11 14:49:43','2026-05-11 14:49:43'],
            [80,'Omkar Jadhav','oj4370574@gmail.com','8181083546','ProTech Solution','Not decided yet','2026-05-11','Sent Project details','BPO Chat Process','active','Indore IND',14,0,NULL,'2026-05-11 14:52:46','2026-05-11 14:52:46'],
            [81,'Sayali Jadhav','sayalijadhav13062001@gmail.com','8432485615',NULL,'Not decided yet','2026-05-11','Sent Project details','BPO Chat Process','active','Satara IND',14,0,NULL,'2026-05-11 14:55:32','2026-05-11 14:55:32'],
            [82,'Hussain Sardar','hussainsardar0@gmail.com','9398002655','Little Hand Tech Solution','Not decided yet','2026-05-11','Sent Project details','BPO Chat Process','active','Andhra Pradesh',14,0,NULL,'2026-05-11 14:57:14','2026-05-11 14:57:14'],
            [83,'Mohammad','khankakhan435@gmail.com','7678047980','Amasa Outsourcing','Not decided yet','2026-05-11','Sent Project details','BPO Chat Process','active','Mumbai',14,0,NULL,'2026-05-11 15:03:51','2026-05-11 15:03:51'],
            [84,'Atul Singh','rajatulsingh6261@gmail.com','6358239202','Shree Enterprises','Not decided yet','2026-05-11','Sent Project details','BPO Chat Process','active','Indore IND',14,0,NULL,'2026-05-11 15:05:44','2026-05-11 15:05:44'],
            [85,'Sunil Kumar','alcjammu@gmail.com','9419105383','Ammay Enterprises','Not decided yet','2026-05-11','Sent Project details','BPO Chat Process','active','Jammu & Kashmir',14,0,NULL,'2026-05-11 15:07:25','2026-05-16 11:52:23'],
            [86,'Amardeep Bhardwaj','AMAR108PANDIT@GMAIL.COM','7697972796',NULL,'Not decided yet','2026-05-11','Sent Project details','BPO Chat Process','active','Indore IND',14,0,NULL,'2026-05-11 15:10:10','2026-05-11 15:10:10'],
            [87,'Saurabh sharma','sharmasourabh609@gmail.com','9399454315','Humex Ai','Not decided yet','2026-05-11','Sent Project details','BPO Chat Process','active','Indore IND',14,0,NULL,'2026-05-11 15:11:36','2026-05-11 15:11:36'],
            [88,'Ritik','ritikbhanushali123@gmail.com','704514480',NULL,'Not decided yet','2026-05-11','Sent Project details','BPO Chat Process','active','Mumbai',14,0,NULL,'2026-05-11 15:13:07','2026-05-11 15:13:07'],
            [89,'Parth SOnar','sonarparth@gmail.com','9075377627','Good shine','Not decided yet','2026-05-11','Sent Project details','BPO Chat Process','active','IND',14,0,NULL,'2026-05-11 15:16:31','2026-05-11 15:16:31'],
            [90,'Devv','support@externix.com','9315067860','Eternix informatics.com','Not decided yet','2026-05-11','Sent Project details','BPO Chat Process','active','IND',14,0,NULL,'2026-05-11 15:19:11','2026-05-11 15:19:11'],
            [91,'Anirban Sanyal','admin@write4uindia.com','7980987521','Write 4u','Not decided yet','2026-05-11','Sent Project details','BPO Chat Process','active','Kolkata IND',14,0,NULL,'2026-05-11 15:23:58','2026-05-11 15:23:58'],
            [92,'Yashwanth Raz','rachakondayash44@gmail.com','8919917650','Ronex Technologies Pvt. Ltd.','Not decided yet','2026-05-11','Sent Project details','BPO Chat Process','active','Hyderabad',14,0,NULL,'2026-05-11 16:32:52','2026-05-11 16:32:52'],
            [93,'Anshu Kumar Ranjan','leonbiolab@gmail.com','7366957500','Leon Bio Lab Pvt. Ltd.','Not decided yet','2026-05-11','Sent Project details','BPO Chat Process','active','Ranchi IND',14,0,NULL,'2026-05-11 16:35:40','2026-05-11 16:35:40'],
            [94,'Vignesh S M','vigneshseerangan99@gmail.com','9677934326',NULL,'Not decided yet','2026-05-11','Sent Project details','BPO Chat Process','active','Salem IND',14,0,NULL,'2026-05-11 16:39:47','2026-05-16 11:54:50'],
        ];

        foreach ($data as $row) {
            DB::table('lead_creates')->insert([
                'id' => $row[0],
                'name' => $row[1],
                'email' => $row[2],
                'phone' => $row[3],
                'company' => $row[4],
                'project_code' => $row[5],
                'date' => $row[6],
                'remarks' => $row[7],
                'project_interested' => $row[8],
                'created_by' => $row[11], // shifting attended_by id to created_by
                'status' => $row[9],
                'location' => $row[10],
                'attended_by' => null, // setting attended_by to null
                'is_deleted' => $row[12],
                'deleted_at' => $row[13],
                'created_at' => $row[14],
                'updated_at' => $row[15],
            ]);
        }

        DB::statement('SET FOREIGN_KEY_CHECKS=1;');
    }
}
