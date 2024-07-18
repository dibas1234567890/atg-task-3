-- MySQL dump 10.16  Distrib 10.1.48-MariaDB, for debian-linux-gnu (x86_64)
--
-- Host: localhost    Database: db
-- ------------------------------------------------------
-- Server version	10.1.48-MariaDB-0+deb9u2

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `auth_group`
--

DROP TABLE IF EXISTS `auth_group`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `auth_group` (
  `id` varchar(0) DEFAULT NULL,
  `name` varchar(0) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `auth_group`
--

LOCK TABLES `auth_group` WRITE;
/*!40000 ALTER TABLE `auth_group` DISABLE KEYS */;
/*!40000 ALTER TABLE `auth_group` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `auth_group_permissions`
--

DROP TABLE IF EXISTS `auth_group_permissions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `auth_group_permissions` (
  `id` varchar(0) DEFAULT NULL,
  `group_id` varchar(0) DEFAULT NULL,
  `permission_id` varchar(0) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `auth_group_permissions`
--

LOCK TABLES `auth_group_permissions` WRITE;
/*!40000 ALTER TABLE `auth_group_permissions` DISABLE KEYS */;
/*!40000 ALTER TABLE `auth_group_permissions` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `auth_permission`
--

DROP TABLE IF EXISTS `auth_permission`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `auth_permission` (
  `id` tinyint(4) DEFAULT NULL,
  `content_type_id` tinyint(4) DEFAULT NULL,
  `codename` varchar(26) DEFAULT NULL,
  `name` varchar(28) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `auth_permission`
--

LOCK TABLES `auth_permission` WRITE;
/*!40000 ALTER TABLE `auth_permission` DISABLE KEYS */;
INSERT INTO `auth_permission` VALUES (1,1,'add_logentry','Can add log entry'),(2,1,'change_logentry','Can change log entry'),(3,1,'delete_logentry','Can delete log entry'),(4,1,'view_logentry','Can view log entry'),(5,2,'add_permission','Can add permission'),(6,2,'change_permission','Can change permission'),(7,2,'delete_permission','Can delete permission'),(8,2,'view_permission','Can view permission'),(9,3,'add_group','Can add group'),(10,3,'change_group','Can change group'),(11,3,'delete_group','Can delete group'),(12,3,'view_group','Can view group'),(13,4,'add_contenttype','Can add content type'),(14,4,'change_contenttype','Can change content type'),(15,4,'delete_contenttype','Can delete content type'),(16,4,'view_contenttype','Can view content type'),(17,5,'add_session','Can add session'),(18,5,'change_session','Can change session'),(19,5,'delete_session','Can delete session'),(20,5,'view_session','Can view session'),(21,6,'add_customeruserprofile','Can add user'),(22,6,'change_customeruserprofile','Can change user'),(23,6,'delete_customeruserprofile','Can delete user'),(24,6,'view_customeruserprofile','Can view user'),(25,7,'add_category','Can add category'),(26,7,'change_category','Can change category'),(27,7,'delete_category','Can delete category'),(28,7,'view_category','Can view category'),(29,8,'add_blogmodel','Can add blog model'),(30,8,'change_blogmodel','Can change blog model'),(31,8,'delete_blogmodel','Can delete blog model'),(32,8,'view_blogmodel','Can view blog model'),(33,9,'add_outstandingtoken','Can add outstanding token'),(34,9,'change_outstandingtoken','Can change outstanding token'),(35,9,'delete_outstandingtoken','Can delete outstanding token'),(36,9,'view_outstandingtoken','Can view outstanding token'),(37,10,'add_blacklistedtoken','Can add blacklisted token'),(38,10,'change_blacklistedtoken','Can change blacklisted token'),(39,10,'delete_blacklistedtoken','Can delete blacklisted token'),(40,10,'view_blacklistedtoken','Can view blacklisted token'),(41,11,'add_token','Can add Token'),(42,11,'change_token','Can change Token'),(43,11,'delete_token','Can delete Token'),(44,11,'view_token','Can view Token'),(45,12,'add_tokenproxy','Can add Token'),(46,12,'change_tokenproxy','Can change Token'),(47,12,'delete_tokenproxy','Can delete Token'),(48,12,'view_tokenproxy','Can view Token');
/*!40000 ALTER TABLE `auth_permission` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `authtoken_token`
--

DROP TABLE IF EXISTS `authtoken_token`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `authtoken_token` (
  `key` varchar(0) DEFAULT NULL,
  `created` varchar(0) DEFAULT NULL,
  `user_id` varchar(0) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `authtoken_token`
--

LOCK TABLES `authtoken_token` WRITE;
/*!40000 ALTER TABLE `authtoken_token` DISABLE KEYS */;
/*!40000 ALTER TABLE `authtoken_token` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `django_admin_log`
--

DROP TABLE IF EXISTS `django_admin_log`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `django_admin_log` (
  `id` varchar(0) DEFAULT NULL,
  `object_id` varchar(0) DEFAULT NULL,
  `object_repr` varchar(0) DEFAULT NULL,
  `action_flag` varchar(0) DEFAULT NULL,
  `change_message` varchar(0) DEFAULT NULL,
  `content_type_id` varchar(0) DEFAULT NULL,
  `user_id` varchar(0) DEFAULT NULL,
  `action_time` varchar(0) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `django_admin_log`
--

LOCK TABLES `django_admin_log` WRITE;
/*!40000 ALTER TABLE `django_admin_log` DISABLE KEYS */;
/*!40000 ALTER TABLE `django_admin_log` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `django_content_type`
--

DROP TABLE IF EXISTS `django_content_type`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `django_content_type` (
  `id` tinyint(4) DEFAULT NULL,
  `app_label` varchar(15) DEFAULT NULL,
  `model` varchar(19) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `django_content_type`
--

LOCK TABLES `django_content_type` WRITE;
/*!40000 ALTER TABLE `django_content_type` DISABLE KEYS */;
INSERT INTO `django_content_type` VALUES (1,'admin','logentry'),(3,'auth','group'),(2,'auth','permission'),(11,'authtoken','token'),(12,'authtoken','tokenproxy'),(4,'contenttypes','contenttype'),(8,'login_system','blogmodel'),(7,'login_system','category'),(6,'login_system','customeruserprofile'),(5,'sessions','session'),(10,'token_blacklist','blacklistedtoken'),(9,'token_blacklist','outstandingtoken');
/*!40000 ALTER TABLE `django_content_type` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `django_migrations`
--

DROP TABLE IF EXISTS `django_migrations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `django_migrations` (
  `id` tinyint(4) DEFAULT NULL,
  `app` varchar(15) DEFAULT NULL,
  `name` varchar(67) DEFAULT NULL,
  `applied` varchar(10) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `django_migrations`
--

LOCK TABLES `django_migrations` WRITE;
/*!40000 ALTER TABLE `django_migrations` DISABLE KEYS */;
INSERT INTO `django_migrations` VALUES (1,'login_system','0001_initial','2024-07-14'),(2,'contenttypes','0001_initial','2024-07-14'),(3,'admin','0001_initial','2024-07-14'),(4,'admin','0002_logentry_remove_auto_add','2024-07-14'),(5,'admin','0003_logentry_add_action_flag_choices','2024-07-14'),(6,'contenttypes','0002_remove_content_type_name','2024-07-14'),(7,'auth','0001_initial','2024-07-14'),(8,'auth','0002_alter_permission_name_max_length','2024-07-14'),(9,'auth','0003_alter_user_email_max_length','2024-07-14'),(10,'auth','0004_alter_user_username_opts','2024-07-14'),(11,'auth','0005_alter_user_last_login_null','2024-07-14'),(12,'auth','0006_require_contenttypes_0002','2024-07-14'),(13,'auth','0007_alter_validators_add_error_messages','2024-07-14'),(14,'auth','0008_alter_user_username_max_length','2024-07-14'),(15,'auth','0009_alter_user_last_name_max_length','2024-07-14'),(16,'auth','0010_alter_group_name_max_length','2024-07-14'),(17,'auth','0011_update_proxy_permissions','2024-07-14'),(18,'auth','0012_alter_user_first_name_max_length','2024-07-14'),(19,'authtoken','0001_initial','2024-07-14'),(20,'authtoken','0002_auto_20160226_1747','2024-07-14'),(21,'authtoken','0003_tokenproxy','2024-07-14'),(22,'authtoken','0004_alter_tokenproxy_options','2024-07-14'),(23,'login_system','0002_alter_customeruserprofile_options_and_more','2024-07-14'),(24,'login_system','0003_rename_confirm_password_customeruserprofile_password1_and_more','2024-07-14'),(25,'login_system','0004_alter_customeruserprofile_managers_and_more','2024-07-14'),(26,'login_system','0005_alter_customeruserprofile_managers','2024-07-14'),(27,'login_system','0006_blogmodel_category','2024-07-14'),(28,'login_system','0007_alter_blogmodel_category','2024-07-14'),(29,'sessions','0001_initial','2024-07-14'),(30,'token_blacklist','0001_initial','2024-07-14'),(31,'token_blacklist','0002_outstandingtoken_jti_hex','2024-07-14'),(32,'token_blacklist','0003_auto_20171017_2007','2024-07-14'),(33,'token_blacklist','0004_auto_20171017_2013','2024-07-14'),(34,'token_blacklist','0005_remove_outstandingtoken_jti','2024-07-14'),(35,'token_blacklist','0006_auto_20171017_2113','2024-07-14'),(36,'token_blacklist','0007_auto_20171017_2214','2024-07-14'),(37,'token_blacklist','0008_migrate_to_bigautofield','2024-07-14'),(38,'token_blacklist','0010_fix_migrate_to_bigautofield','2024-07-14'),(39,'token_blacklist','0011_linearizes_history','2024-07-14'),(40,'token_blacklist','0012_alter_outstandingtoken_user','2024-07-14'),(41,'login_system','0008_customuserprofile_delete_customeruserprofile','2024-07-14'),(42,'login_system','0009_rename_customuserprofile_customeruserprofile','2024-07-14'),(43,'login_system','0010_rename_categeory_name_category_category_name','2024-07-14'),(44,'login_system','0011_blogmodel_user','2024-07-14'),(45,'login_system','0012_alter_blogmodel_user','2024-07-14'),(46,'login_system','0013_alter_blogmodel_user','2024-07-14');
/*!40000 ALTER TABLE `django_migrations` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `django_session`
--

DROP TABLE IF EXISTS `django_session`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `django_session` (
  `session_key` varchar(32) DEFAULT NULL,
  `session_data` varchar(227) DEFAULT NULL,
  `expire_date` varchar(10) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `django_session`
--

LOCK TABLES `django_session` WRITE;
/*!40000 ALTER TABLE `django_session` DISABLE KEYS */;
INSERT INTO `django_session` VALUES ('4roagenkjwtupallccgsjaedfy5elf4h','.eJxVjEEOwiAQAP_C2RBgt9B69N43kGUXbNXQpLQn499Nkx70OjOZt4q0b1PcW17jLOqqQF1-WSJ-5noIeVC9L5qXuq1z0keiT9v0uEh-3c72bzBRm45t32VHKMWXrjjqgQXYu2QQrYEhBCPWC9pkwRMDGLDDgBysd9yVgOrzBdCTNtQ:1sT9gg:5DAEvrZNgXzZGx_kWzYEi6sowiALCwHgnhFZU3Vg3MQ','2024-07-29');
/*!40000 ALTER TABLE `django_session` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `login_system_blogmodel`
--

DROP TABLE IF EXISTS `login_system_blogmodel`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `login_system_blogmodel` (
  `id` tinyint(4) DEFAULT NULL,
  `title` varchar(4) DEFAULT NULL,
  `image` varchar(60) DEFAULT NULL,
  `category_id` tinyint(4) DEFAULT NULL,
  `summary` varchar(4) DEFAULT NULL,
  `content` varchar(4) DEFAULT NULL,
  `status` varchar(5) DEFAULT NULL,
  `user_id` tinyint(4) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `login_system_blogmodel`
--

LOCK TABLES `login_system_blogmodel` WRITE;
/*!40000 ALTER TABLE `login_system_blogmodel` DISABLE KEYS */;
INSERT INTO `login_system_blogmodel` VALUES (1,'dsa','stethoscope-stock-photography-clip-art-stetoskop_pWgGJqN.jpg',1,'dsa','dsa','draft',1),(2,'Test','stethoscope-stock-photography-clip-art-stetoskop_tOzuvDW.jpg',1,'Test','Test','draft',2);
/*!40000 ALTER TABLE `login_system_blogmodel` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `login_system_category`
--

DROP TABLE IF EXISTS `login_system_category`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `login_system_category` (
  `id` tinyint(4) DEFAULT NULL,
  `category_name` varchar(28) DEFAULT NULL,
  `category_slug` varchar(28) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `login_system_category`
--

LOCK TABLES `login_system_category` WRITE;
/*!40000 ALTER TABLE `login_system_category` DISABLE KEYS */;
INSERT INTO `login_system_category` VALUES (1,'In The News','in-the-news'),(2,'New Research','new-research'),(3,'What The Medicos Have To Say','what-the-medicos-have-to-say'),(4,'Mental Health','mental-health'),(5,'New Research','new-research');
/*!40000 ALTER TABLE `login_system_category` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `login_system_customeruserprofile`
--

DROP TABLE IF EXISTS `login_system_customeruserprofile`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `login_system_customeruserprofile` (
  `id` tinyint(4) DEFAULT NULL,
  `password` varchar(88) DEFAULT NULL,
  `last_login` varchar(10) DEFAULT NULL,
  `is_superuser` tinyint(4) DEFAULT NULL,
  `is_staff` tinyint(4) DEFAULT NULL,
  `is_active` tinyint(4) DEFAULT NULL,
  `date_joined` varchar(10) DEFAULT NULL,
  `first_name` varchar(18) DEFAULT NULL,
  `last_name` varchar(18) DEFAULT NULL,
  `profile_picture` varchar(73) DEFAULT NULL,
  `username` varchar(18) DEFAULT NULL,
  `email` varchar(21) DEFAULT NULL,
  `password1` varchar(0) DEFAULT NULL,
  `password2` varchar(0) DEFAULT NULL,
  `address_line1` varchar(9) DEFAULT NULL,
  `city` varchar(9) DEFAULT NULL,
  `state` varchar(7) DEFAULT NULL,
  `pincode` varchar(5) DEFAULT NULL,
  `user_type` varchar(7) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `login_system_customeruserprofile`
--

LOCK TABLES `login_system_customeruserprofile` WRITE;
/*!40000 ALTER TABLE `login_system_customeruserprofile` DISABLE KEYS */;
INSERT INTO `login_system_customeruserprofile` VALUES (1,'pbkdf2_sha256$600000$rlEIEwRpb0IYviwyGlAhkw$oSb9swbYJmWI49rJCZeTy09yXpTJdhUw6kfz1qDDpu8=','',0,0,1,'2024-07-14','Dibas UserLinkTEST','Dibas UserLinkTEST','profile_pics/stethoscope-stock-photography-clip-art-stetoskop.jpg','Dibas UserLinkTEST','dibas@user.com','','','Baluwatar','Kathmandu','Bagmati','44600','patient'),(2,'pbkdf2_sha256$600000$KAZbt5S0SiCg94wO47MxU2$xhBkoc0D6EC55VePIScKS3W1ovt2ue4S4jwPyIMvQEE=','',0,0,1,'2024-07-15','S','S','profile_pics/stethoscope-stock-photography-clip-art-stetoskop_WKUYSZt.jpg','Dibas','dibaspratap@gmail.com','','','Baluwatar','Kathmandu','Bagmati','44600','doctor'),(3,'pbkdf2_sha256$600000$RYZbCOZl6tVokbGwoXP9jf$nBoiIttV4xsf8w7uTtZCu+tsV2xlU9ym7vXEbVSJVLo=','2024-07-15',1,1,1,'2024-07-15','','','','admin','admin@admin.com','','','','','','','');
/*!40000 ALTER TABLE `login_system_customeruserprofile` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `login_system_customeruserprofile_groups`
--

DROP TABLE IF EXISTS `login_system_customeruserprofile_groups`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `login_system_customeruserprofile_groups` (
  `id` varchar(0) DEFAULT NULL,
  `customeruserprofile_id` varchar(0) DEFAULT NULL,
  `group_id` varchar(0) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `login_system_customeruserprofile_groups`
--

LOCK TABLES `login_system_customeruserprofile_groups` WRITE;
/*!40000 ALTER TABLE `login_system_customeruserprofile_groups` DISABLE KEYS */;
/*!40000 ALTER TABLE `login_system_customeruserprofile_groups` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `login_system_customeruserprofile_user_permissions`
--

DROP TABLE IF EXISTS `login_system_customeruserprofile_user_permissions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `login_system_customeruserprofile_user_permissions` (
  `id` varchar(0) DEFAULT NULL,
  `customeruserprofile_id` varchar(0) DEFAULT NULL,
  `permission_id` varchar(0) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `login_system_customeruserprofile_user_permissions`
--

LOCK TABLES `login_system_customeruserprofile_user_permissions` WRITE;
/*!40000 ALTER TABLE `login_system_customeruserprofile_user_permissions` DISABLE KEYS */;
/*!40000 ALTER TABLE `login_system_customeruserprofile_user_permissions` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `sqlite_sequence`
--

DROP TABLE IF EXISTS `sqlite_sequence`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `sqlite_sequence` (
  `name` varchar(49) DEFAULT NULL,
  `seq` tinyint(4) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `sqlite_sequence`
--

LOCK TABLES `sqlite_sequence` WRITE;
/*!40000 ALTER TABLE `sqlite_sequence` DISABLE KEYS */;
INSERT INTO `sqlite_sequence` VALUES ('django_migrations',46),('django_admin_log',0),('django_content_type',12),('auth_permission',48),('auth_group',0),('token_blacklist_blacklistedtoken',0),('token_blacklist_outstandingtoken',5),('login_system_customeruserprofile_groups',0),('login_system_customeruserprofile_user_permissions',0),('login_system_customeruserprofile',3),('login_system_category',5),('login_system_blogmodel',2);
/*!40000 ALTER TABLE `sqlite_sequence` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `token_blacklist_blacklistedtoken`
--

DROP TABLE IF EXISTS `token_blacklist_blacklistedtoken`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `token_blacklist_blacklistedtoken` (
  `blacklisted_at` varchar(0) DEFAULT NULL,
  `token_id` varchar(0) DEFAULT NULL,
  `id` varchar(0) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `token_blacklist_blacklistedtoken`
--

LOCK TABLES `token_blacklist_blacklistedtoken` WRITE;
/*!40000 ALTER TABLE `token_blacklist_blacklistedtoken` DISABLE KEYS */;
/*!40000 ALTER TABLE `token_blacklist_blacklistedtoken` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `token_blacklist_outstandingtoken`
--

DROP TABLE IF EXISTS `token_blacklist_outstandingtoken`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `token_blacklist_outstandingtoken` (
  `token` varchar(229) DEFAULT NULL,
  `created_at` varchar(10) DEFAULT NULL,
  `expires_at` varchar(0) DEFAULT NULL,
  `user_id` tinyint(4) DEFAULT NULL,
  `jti` varchar(32) DEFAULT NULL,
  `id` tinyint(4) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `token_blacklist_outstandingtoken`
--

LOCK TABLES `token_blacklist_outstandingtoken` WRITE;
/*!40000 ALTER TABLE `token_blacklist_outstandingtoken` DISABLE KEYS */;
INSERT INTO `token_blacklist_outstandingtoken` VALUES ('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl90eXBlIjoicmVmcmVzaCIsImV4cCI6MTcyMTA4NTMzOCwiaWF0IjoxNzIwOTk4OTM4LCJqdGkiOiI1OTdkYjEwYmZiMGY0YjMxYTY0MGJmZWE1YzI5MjExZSIsInVzZXJfaWQiOjF9.58JWfwsZUcN_IEpcJwhYsIOHkJ6vfin2QM01JWI88sM','2024-07-14','',1,'597db10bfb0f4b31a640bfea5c29211e',1),('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl90eXBlIjoicmVmcmVzaCIsImV4cCI6MTcyMTA4NzEyMiwiaWF0IjoxNzIxMDAwNzIyLCJqdGkiOiIxODRlMjkwYjUxMDk0ZDQxODJlZmQ2MTViZDczOGE5YiIsInVzZXJfaWQiOjF9.7Oqbt6funmlZuWhnTU24lXk_ZMnKvGcIQa__ws--HSg','2024-07-14','',1,'184e290b51094d4182efd615bd738a9b',2),('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl90eXBlIjoicmVmcmVzaCIsImV4cCI6MTcyMTA4OTA3OSwiaWF0IjoxNzIxMDAyNjc5LCJqdGkiOiI5YzZlNWQ0YjE2ODU0ZmVkOTM5NWI4NDA5NmIyODU4MyIsInVzZXJfaWQiOjJ9.4R0n3irfOMCCiYUnfw8rbffE0WmAHFIs8LdxBCpgUDw','2024-07-15','',2,'9c6e5d4b16854fed9395b84096b28583',3),('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl90eXBlIjoicmVmcmVzaCIsImV4cCI6MTcyMTA5MDcwMiwiaWF0IjoxNzIxMDA0MzAyLCJqdGkiOiJlZDgxMzMwNWUzMDE0MDBkOGYyOTMxZGU3YWZlZjRlMSIsInVzZXJfaWQiOjF9.i81CNztnznsdYQ2j8hoQVxBKCzAM9H17xoHDFhiHj4E','2024-07-15','',1,'ed813305e301400d8f2931de7afef4e1',4),('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl90eXBlIjoicmVmcmVzaCIsImV4cCI6MTcyMTA5MDgxNywiaWF0IjoxNzIxMDA0NDE3LCJqdGkiOiIxZTg4MjUxMDhhMzg0YmVmYjIwMTFlOWU4NmIxNjY4ZCIsInVzZXJfaWQiOjJ9.nPo164KA0pi97KHey2lwxiwdWUnWRPHprb5uAWXZEuk','2024-07-15','',2,'1e8825108a384befb2011e9e86b1668d',5);
/*!40000 ALTER TABLE `token_blacklist_outstandingtoken` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2024-04-30 16:42:47
