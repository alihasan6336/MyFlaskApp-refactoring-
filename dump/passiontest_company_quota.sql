-- MySQL dump 10.13  Distrib 8.0.20, for Win64 (x86_64)
--
-- Host: 127.0.0.1    Database: passiontest
-- ------------------------------------------------------
-- Server version	8.0.20

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `company_quota`
--

DROP TABLE IF EXISTS `company_quota`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `company_quota` (
  `id` mediumint unsigned NOT NULL AUTO_INCREMENT,
  `company` varchar(45) NOT NULL,
  `quota` int DEFAULT NULL,
  `date` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=54 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `company_quota`
--

LOCK TABLES `company_quota` WRITE;
/*!40000 ALTER TABLE `company_quota` DISABLE KEYS */;
INSERT INTO `company_quota` VALUES (1,'passion',0,'2020-09-15 08:33:19'),(2,'voda',8,'2020-09-15 08:37:22'),(3,'afasf',5,'2020-09-15 15:27:48'),(4,'afasf',3,'2020-09-15 15:30:54'),(5,'afasf',1,'2020-09-15 15:31:27'),(6,'afasf',1,'2020-09-15 15:31:45'),(7,'passion',0,'2020-09-15 19:52:03'),(8,'passion',0,'2020-09-15 19:52:52'),(9,'passion',0,'2020-09-15 19:53:18'),(10,'passion',0,'2020-09-15 19:53:43'),(11,'passion',0,'2020-09-15 19:54:10'),(12,'passion',0,'2020-09-15 19:55:07'),(13,'passion',0,'2020-09-15 19:55:46'),(14,'passion',0,'2020-09-15 19:56:13'),(15,'passion',0,'2020-09-15 19:56:43'),(16,'passion',0,'2020-09-15 19:58:42'),(17,'passion',1,'2020-09-15 19:58:47'),(18,'passion',1,'2020-09-15 19:58:49'),(19,'passion',-1,'2020-09-15 19:58:56'),(20,'passion',100,'2020-09-15 19:59:02'),(21,'passion',-95,'2020-09-15 19:59:08'),(22,'username',1,'2020-09-15 19:59:12'),(23,'username',1,'2020-09-15 20:00:26'),(24,'username',1,'2020-09-15 20:00:37'),(25,'dasdasdasd',1,'2020-09-15 20:00:41'),(26,'dasdasdasd',-1,'2020-09-15 20:00:45'),(27,'dasdasdasd',1,'2020-09-15 20:00:49'),(28,'aaa',0,'2020-09-15 20:03:24'),(29,'dsfaassdf',0,'2020-09-15 20:03:30'),(30,'aaa',5,'2020-09-15 20:03:38'),(31,'aaa',-3,'2020-09-15 20:03:41'),(32,'passion',100000,'2020-09-15 20:03:59'),(33,'voda',500,'2020-09-15 20:06:10'),(34,'voda',11,'2020-09-15 21:03:28'),(35,'voda',-1155,'2020-09-15 21:03:34'),(36,'voda',604,'2020-09-15 21:03:55'),(37,'voda',604,'2020-09-15 21:04:09'),(38,'voda',604,'2020-09-15 21:04:25'),(39,'voda',-1208,'2020-09-15 21:04:35'),(40,'voda',-1,'2020-09-15 21:04:40'),(41,'aaa',400,'2020-09-15 21:09:50'),(42,'passion',-1000,'2020-09-15 21:13:23'),(43,'passion',2,'2020-09-16 13:55:28'),(44,'voda',1,'2020-09-16 21:23:12'),(45,'afasf',11,'2020-09-16 21:23:16'),(46,'afasf',1,'2020-09-16 21:23:18'),(47,'afasf',-1,'2020-09-16 21:23:22'),(48,'afasf',0,'2020-09-17 11:09:33'),(49,'afasf',1,'2020-09-17 11:09:35'),(50,'afasf',-10,'2020-09-17 11:09:40'),(51,'wee',1,'2020-09-17 15:00:08'),(52,'wee',1,'2020-09-17 19:37:16'),(53,'wee',1200,'2020-09-17 19:37:35');
/*!40000 ALTER TABLE `company_quota` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2020-09-18  0:40:31
