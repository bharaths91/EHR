-- MySQL dump 10.13  Distrib 8.0.27, for Win64 (x86_64)
--
-- Host: localhost    Database: ehr_final
-- ------------------------------------------------------
-- Server version	8.0.27

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
-- Table structure for table `m_dataowner`
--

DROP TABLE IF EXISTS `m_dataowner`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `m_dataowner` (
  `do_id` int NOT NULL AUTO_INCREMENT,
  `do_code` varchar(45) DEFAULT NULL,
  `do_password` varchar(45) DEFAULT NULL,
  `do_name` varchar(45) DEFAULT NULL,
  `do_email` varchar(45) DEFAULT NULL,
  `do_algorithm` varchar(20) DEFAULT NULL,
  `do_encryption_key` varchar(500) DEFAULT NULL,
  `do_decryption_key` varchar(500) DEFAULT NULL,
  PRIMARY KEY (`do_id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `m_dataowner`
--

LOCK TABLES `m_dataowner` WRITE;
/*!40000 ALTER TABLE `m_dataowner` DISABLE KEYS */;
INSERT INTO `m_dataowner` VALUES (1,'101','himan123','himan','himanbabu@gmail.com','rsa','-----BEGIN RSA PUBLIC KEY-----\nMBgCEQC41RrnD9NGNftl7l6aSlnvAgMBAAE=\n-----END RSA PUBLIC KEY-----\n','-----BEGIN RSA PRIVATE KEY-----\nMGMCAQACEQC41RrnD9NGNftl7l6aSlnvAgMBAAECEQCG3CbW9PsIs6nZU0Li5KaR\nAgkNjHbuaCynTzUCCA2kX/60Q7UTAgkCT72WrQU5QiUCCAyrhGhnfZa3AgkJMA4h\nIVoBRlY=\n-----END RSA PRIVATE KEY-----\n'),(2,'102','chinni123','chinni','chinni@gmail.com','ecc','38115923942545073557116516189256100173757439850435142314813271478248378628208','38115923942545073557116516189256100173757439850435142314813271478248378628208');
/*!40000 ALTER TABLE `m_dataowner` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2023-07-20 17:36:43
