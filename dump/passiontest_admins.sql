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
-- Table structure for table `admins`
--

DROP TABLE IF EXISTS `admins`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `admins` (
  `id` smallint unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(50) NOT NULL,
  `phone` varchar(50) NOT NULL,
  `password` varchar(256) NOT NULL,
  `date` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `admin` tinyint(1) DEFAULT '0',
  `can_d` tinyint(1) DEFAULT '0',
  `company` varchar(45) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_index` (`phone`,`company`)
) ENGINE=InnoDB AUTO_INCREMENT=17 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `admins`
--

LOCK TABLES `admins` WRITE;
/*!40000 ALTER TABLE `admins` DISABLE KEYS */;
INSERT INTO `admins` VALUES (1,'ali','01019056637','$5$rounds=535000$HB0Vjm6.eiL4PP9I$hwwjtZfkk7H.MKOAE5vHd49EF8kJsMV2P8wbFggsp7/','2020-05-17 22:11:10',1,1,'passion'),(2,'aaaa','11111111','$5$rounds=535000$bNiJRb5lf3QN8ih1$qBKOrQJ6Qe9nfZWrmR1FxHrBF.3/d3JHJx6471gvWh.','2020-05-19 14:50:07',1,0,'passion'),(3,'aa','13202654','$5$rounds=535000$FuzyE9V7H2BvLNob$W8afvSfX/vYV8QFcpRA53rRyF3O79oiazZDuTM5xOg4','2020-09-09 20:50:23',0,1,'passion'),(4,'aa','021595201','$5$rounds=535000$e/GD0YEu.b5yhR2L$71idLYfjtpiFe8ZrHPFTgQF9U0lGjf43yl/NVGjDiP6','2020-09-09 20:51:22',1,1,'username'),(5,'aasd','125498520','$5$rounds=535000$HyuDMH0VZlCld93I$NfD0GU/FCrpkHxUuB8Dco7iCMrl1jYL59uJC8hPMdWB','2020-09-10 15:51:32',0,0,'passion'),(6,'voda','0101010101','$5$rounds=535000$ywKUwRSaFiTgoXBa$yD5Y9gVHpsViPJcEnix7y33K0QUMxuyGSzEZp.q1Du0','2020-09-10 15:55:38',1,0,'voda'),(7,'aaaa','152365420','$5$rounds=535000$lhxRKn64WpFl3W8d$hFnqHZrqZyt.cmFeBmnCwH78chUSPFmYguuiVtxuSRD','2020-09-10 16:02:56',1,1,'voda'),(8,'987987987','987987987','$5$rounds=535000$cmsqetsg46x.A72.$jVa7TOqMYUlAn6dKnJAE8j7V0usBrFrR0zHNEwvCkd/','2020-09-13 23:13:14',1,1,'voda'),(9,'987987987','987987987','$5$rounds=535000$opIrtM1pWilsz8wf$9cQ4wRYD8Lixn9dp7hF0i4NYsog5PrShJQyae6EsK13','2020-09-13 23:13:35',0,0,'passion'),(10,'987987987','987987987','$5$rounds=535000$B.ZfNOS9y8Y/MMlF$98VIkZo2hACWjYKIvjAZoLQZpSn.rPnNSWDkt2j05l1','2020-09-13 23:14:53',0,0,'saasd'),(12,'abdo','012301230154','$5$rounds=535000$uNlkJGPJ2enLjzIM$NYKV4BxjbiCZtmf8nvjNHbKsW9k2frAR213mGttTca7','2020-09-15 20:07:44',0,0,'passion'),(13,'link','012301254205','$5$rounds=535000$G7b536kunaAQB1xq$uxsbpD1W2tjirtrcAH/2PzA3wf5.K6qcA3Ai6tbdpI0','2020-09-15 20:08:50',0,0,'voda'),(14,'wee admin','01234567899','$5$rounds=535000$wQScLqAnhlaMUo8A$Af.P0MhTK4VyhcQ/cvTqWNvMUc.MYwpfeoUuBKYQsg4','2020-09-15 20:52:58',1,0,'wee'),(15,'admin','111111111111','$5$rounds=535000$RA4F85LRmzxlVlDz$BAd2X1x4ADRHcp02vtzemrYlieBWmlDR8AG4pPhKdCA','2020-09-17 10:17:49',1,0,'passion'),(16,'012345678999','012345678999','$5$rounds=535000$nepyGMxn.A/IPoDS$OlyVfG4h7pARGNf4WLvGVbvQSr.uBh9wxvbsPMIsC22','2020-09-17 15:04:24',0,1,'wee');
/*!40000 ALTER TABLE `admins` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2020-09-18  0:40:30
