#ifndef MERCURY230_PROTO_H
#define MERCURY230_PROTO_H

#define PASS_1 "\1\1\1\1\1\1"   // binary: 0x01,0x01,0x01,0x01,0x01,0x01 (user default)
#define PASS_2 "\2\2\2\2\2\2"   // binary: 0x02,0x02,0x02,0x02,0x02,0x02 (admin default)
#define PASS_DEFAULT_1 "\1\1\1\1\1\1"  // user password (0x01 bytes)
#define PASS_DEFAULT_2 "\2\2\2\2\2\2"  // admin password (0x02 bytes)

#define PACKET_MIN_DELAY 1000  // Увеличено для надёжного приёма ответов
#define ABORT_RECIVE_TIME 200  // Таймаут приёма байта увеличен
#define MIN_SCAN_PERIOD 2000


        //============================ ПЕРЕМЕННЫЕ =======================
        uint8_t readBuff[32] = {0}; // буфер входящих данных
        uint8_t fromReadArrow = 0; // указатель точки заполнения буфера приема
        uint8_t sendBuff[32] = {0}; // буфер отправки
        _sBuff* sBuff = (_sBuff*)sendBuff; // фантом буфера отправки
        uint8_t forSendSize = 0; // количество данных в буфере отправки
        uint8_t forSendArrow = 0; // указатель на очередной байт в буфере для отправки 
        _currentSend forSenfType = NONE; // тип пакета в буфере отправки, что ждем от пакета приема
        uint32_t scanPeriod = 0xFFFFFFFF; // период сканирования
        uint32_t timeReadByte=0; //тут время последнего получения байта
        uint32_t timeSendByte=0; //время последней отправки байта
        uint16_t mainCRC=0; // CRC прибора
        bool procError=false; // если во время цикла опроса возикнет ошибка
        bool waiteReply = false; // флаг ожидания ответа, поднимается при отправке, снимается при получении
        _replyReason lastError=REP_OK; // последний статус ответа
        uint32_t scanTimer=millis(); // таймер периодов связи
        uint8_t password_attempt=0; // счетчик попыток пароля (0=222222, 1=111111, 2=user)

        //==================== ОБМЕН ДАННЫМИ ===================================
        // таблица быстрого рассчета КС
        uint16_t crcTable[256] = {
            0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
            0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
            0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
            0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
            0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
            0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
            0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
            0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
            0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
            0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
            0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
            0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
            0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
            0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
            0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
            0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
            0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
            0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
            0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
            0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
            0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
            0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
            0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
            0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
            0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
            0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
            0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
            0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
            0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
            0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
            0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
            0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040
        };
        
        // дебильный формат меркурия, программист дятел.
        uint32_t dm32_3(uint8_t* d){
            return (((((uint32_t)(d[0]&0x3f))<<8)+d[2])<<8)+d[1];  
        }
        uint32_t dm32_4(uint8_t* d){
            return (((((((uint32_t)d[1])<<8)+d[0])<<8)+d[3])<<8)+d[2];  
        }

        // для подсчета CS на лету
        uint16_t stepCrc16mb(uint8_t in, bool start=false){
            static uint16_t crc=0xFFFF;
            if(start){ // первое обращение
                crc=0xFFFF;     
            }
            crc = ((crc >> 8) ^ crcTable[(crc ^ in) & 0xFF]);
            return crc;
        }
        // подсчет контрольной суммы сразу в буфере
        uint8_t crc16mb(uint8_t *s, uint8_t count) {
            uint16_t crc = 0xFFFF;
            for(int i = 0; i < count-2; i++) {
                crc = ((crc >> 8) ^ crcTable[(crc ^ s[i]) & 0xFF]);
            }
            s[count-2] = (uint8_t)(crc & 0xFF);
            s[count-1] = (uint8_t)(crc >> 8);
            if(debugOut){ // показываем буфер для отладки
                inDataReady(count, sendBuff); 
            }
            return count;
        }
        
        // получить пароль из настроек
        bool getPass(uint8_t* buff){
            if(act_pass==false){ // нет установленного пароля
               return false;
            }
            // Пароль передается как ASCII символы (например "111111" = 0x31,0x31,0x31,0x31,0x31,0x31)
            for(uint8_t i=0;i<6;i++){
                buff[i]=pass[i];    
            }
            ESP_LOGD("Mercury", "User password for send: %02X,%02X,%02X,%02X,%02X,%02X",buff[0],buff[1],buff[2],buff[3],buff[4],buff[5]);
            return true;
        }

        // открытие канала связи, безадресная
        void sConnect(){
            sBuff->addr=addr;
            sBuff->packType=_OK;
            forSendSize = crc16mb(sendBuff, 4); // размер пакета
            forSendArrow = 0;
            forSenfType = GET_TEST;
        }
        // загрузка пользовательского пароля в буфер
        void setpass(uint8_t* buff, uint32_t pass){
            
            for(uint8_t i=0;i<6;i++){
               
            }
        }
        
        // запрос доступа, по умолчанию с паролем пользователя
        void sAccess(){
            sBuff->addr = addr;
            sBuff->packType=CONNECT;
            if(admin){
                sBuff->data[0]=2; // уровень доступа
                if(password_attempt == 0){
                    memcpy(sBuff->data+1, PASS_DEFAULT_1, 6);
                    ESP_LOGD("Mercury", "Trying admin password 0x02*6 (attempt %d)", password_attempt);
                } else if(password_attempt == 1){
                    memcpy(sBuff->data+1, PASS_DEFAULT_2, 6);
                    ESP_LOGD("Mercury", "Trying admin password 0x01*6 (attempt %d)", password_attempt);
                } else if(act_pass){
                    getPass(sBuff->data+1);
                    ESP_LOGD("Mercury", "Trying user password (attempt %d)", password_attempt);
                } else {
                   memcpy(sBuff->data+1, PASS_2, 6);
                }
            } else {
                sBuff->data[0]=1; // уровень доступа
                if(password_attempt == 0){
                    memcpy(sBuff->data+1, PASS_DEFAULT_1, 6);
                    ESP_LOGD("Mercury", "Trying user password 0x01*6 (attempt %d)", password_attempt);
                } else if(password_attempt == 1){
                    memcpy(sBuff->data+1, PASS_DEFAULT_2, 6);
                    ESP_LOGD("Mercury", "Trying user password 0x02*6 (attempt %d)", password_attempt);
                } else if(act_pass){
                    getPass(sBuff->data+1);
                    ESP_LOGD("Mercury", "Trying user password (attempt %d)", password_attempt);
                } else {
                   memcpy(sBuff->data+1, PASS_1, 6);
                }
            }
            forSendSize = crc16mb(sendBuff, 11);
            forSendArrow = 0;
            forSenfType = GET_ACCESS;
            ESP_LOGD("Mercury", "Authorization packet prepared, size: %d bytes", forSendSize);
        }

        // предварительная подготовка к запросу параметров 6 байт
        void _getParam(uint8_t param){
            sBuff->addr = addr;
            sBuff->packType = READ_PARAMS;
            sBuff->data[0]=(uint8_t)PARAM_ALL;
            sBuff->data[1]=param;
            forSendSize = crc16mb(sendBuff, 6); // возврат размера пакета
            forSendArrow = 0;
        }
        //мощность P, все фазы
        void sGetPower(){ _getParam(0); forSenfType = GET_POWER;}
        // напряжение, для группового запроса указываем первую фазу
        void sGetVoltage(){ _getParam(0x11); forSenfType = GET_VOLTAGE;};
        // ток, для группового запроса указываем первую фазу
        void sGetCurrent(){ _getParam(0x21); forSenfType = GET_CURRENT;};
        // коэффициетны мошности, для группового запроса указываем первую фазу
        void sGetKoefPower(){ _getParam(0x31); forSenfType = GET_KOEF_POWER;};
        // запрос частоты
        void sGetFreq(){ _getParam(0x40); forSenfType = GET_FREQ;};
        // углы, для группового запроса указываем первую фазу
        void sGetAnglePh(){_getParam(0x51); forSenfType = GET_ANGLE_PH;};
        //запрос параметров устройства
        void sGetVers(){
            sBuff->addr = addr;
            sBuff->packType = READ_PARAMS;
            sBuff->data[0]=1;
            forSendSize = crc16mb(sendBuff, 5);
            forSendArrow = 0;
            forSenfType = GET_VERS;
        }
        //запрос сетевого адреса
        void sGetAddr(){
            sBuff->addr = 0; 
            sBuff->packType = READ_PARAMS;
            sBuff->data[0] = 5; // параметр номер счетчика
            forSendSize = crc16mb(sendBuff, 5);
            forSendArrow = 0;
            forSenfType = GET_ADDR;
        }
        // запрос показаний
        void sGetValue_A(){
            sBuff->addr=addr;
            sBuff->packType = LIST; // 0x05
            sBuff->data[0] = 0x00; // от сброса (нарастающий итог)
            sBuff->data[1] = 0x01; // тариф 1
            forSendSize = crc16mb(sendBuff,6);
            forSendArrow = 0;
            forSenfType = GET_VALUE_A;
        }
	
        void sGetValue_B(){
            sBuff->addr=addr;
            sBuff->packType = LIST; // 0x05
            sBuff->data[0] = 0x00; // от сброса (нарастающий итог)
            sBuff->data[1] = 0x02; // тариф 2
            forSendSize = crc16mb(sendBuff,6);
            forSendArrow = 0;
            forSenfType = GET_VALUE_B;
        }
        void sGetValue_C(){
            sBuff->addr=addr;
            sBuff->packType = LIST; // 0x05
            sBuff->data[0] = 0x00; // от сброса (нарастающий итог)
            sBuff->data[1] = 0x03; // тариф 3
            forSendSize = crc16mb(sendBuff,6);
            forSendArrow = 0;
            forSenfType = GET_VALUE_C;
        }

        void sGetTemp(){
            sBuff->addr = addr;
            sBuff->packType = READ_PARAMS; // 0x08
            sBuff->data[0] = 0x11; // одиночный формат ответа
            sBuff->data[1] = 0x70; // BWRI: температура внутри корпуса
            forSendSize = crc16mb(sendBuff, 6);
            forSendArrow = 0;
            forSenfType = GET_TEMP;
        }
        void sGetPhaseEnergyA(){
            sBuff->addr = addr;
            sBuff->packType = LIST; // 0x05
            sBuff->data[0] = 0x61; // период 6h фаза 1
            sBuff->data[1] = 0x00; // тариф 0 = сумма тарифов
            forSendSize = crc16mb(sendBuff, 6);
            forSendArrow = 0;
            forSenfType = GET_PHASE_ENERGY_A;
        }
        void sGetPhaseEnergyB(){
            sBuff->addr = addr;
            sBuff->packType = LIST; // 0x05
            sBuff->data[0] = 0x62; // период 6h фаза 2
            sBuff->data[1] = 0x00;
            forSendSize = crc16mb(sendBuff, 6);
            forSendArrow = 0;
            forSenfType = GET_PHASE_ENERGY_B;
        }
        void sGetPhaseEnergyC(){
            sBuff->addr = addr;
            sBuff->packType = LIST; // 0x05
            sBuff->data[0] = 0x63; // период 6h фаза 3
            sBuff->data[1] = 0x00;
            forSendSize = crc16mb(sendBuff, 6);
            forSendArrow = 0;
            forSenfType = GET_PHASE_ENERGY_C;
        }

        // возврат ошибок
        _replyReason getLastError(){
            return lastError;
        }
        char* getStrError(_replyReason lastError){
            static char out[27]={0};
            char* rep=out;
            if((uint8_t)lastError & 0x80){ // это широковещалка
                lastError = (_replyReason)((uint8_t)lastError & 0x7F);
                strcpy(rep, "Broadcast ");
                rep+=10; //размер тега "Broadcast "    
            }
            if(lastError==REP_OK){
                strcpy(rep,"OK");
            } else if (lastError==ERROR_COMMAND){
                strcpy(rep,"Command error");
            } else if (lastError==ERROR_HARDWARE){
                strcpy(rep,"Hardware error");
            } else if (lastError==ERROR_ACCESS_LEVEL){
                strcpy(rep,"Access deny");
            } else if (lastError==ERROR_CORE_TIME){
                strcpy(rep,"Core time forbiden");
            } else if (lastError==ERROR_CONNECTION){
                strcpy(rep,"Connection close");
            } else if(lastError==ERROR_TIMEOUT){
                strcpy(rep,"Timeout error");
            } else if(lastError==BUFFER_OVERFLOW){
                strcpy(rep,"Buffer overflow");
            } else {
                strcpy(rep,"Unexpected");
            }
            return out;
        }

        // функции для публикации
        void _cbPower(float Psumm, float Pa, float Pb, float Pc){// будет вызвана при чтении из счетчика мощности
            static float _Pa=-_Pa; 
            static float _Pb=-_Pb; 
            static float _Pc=-_Pc; 
            static float _Psumm=-_Psumm;
            if(this->Watts!=nullptr && _Psumm!=Psumm){_Psumm=Psumm; this->Watts->publish_state(Psumm);}
            if(this->WattA!=nullptr && _Pa!=Pa){_Pa=Pa; this->WattA->publish_state(Pa);}
            if(this->WattB!=nullptr && _Pb!=Pb){_Pb=Pb; this->WattB->publish_state(Pb);}
            if(this->WattC!=nullptr && _Pc!=Pc){_Pc=Pc; this->WattC->publish_state(Pc);}
        }
        void _cbVolt(float Va, float Vb, float Vc){//  будет вызвана при чтении из счетчика напряжения
            static float _Va=_Va; 
            static float _Vb=_Vb; 
            static float _Vc=_Vc; 
            if(this->VoltA!=nullptr && _Va!=Va){_Va=Va; this->VoltA->publish_state(Va);}
            if(this->VoltB!=nullptr && _Vb!=Vb){_Vb=Vb; this->VoltB->publish_state(Vb);}
            if(this->VoltC!=nullptr && _Vc!=Vc){_Vc=Vc; this->VoltC->publish_state(Vc);}
        }
        void _cbCurrent(float Ca, float Cb, float Cc){// будет вызвана при чтении из счетчика токов
            bool change_summ=false;
            static float _Ca=-_Ca; 
            static float _Cb=-_Cb; 
            static float _Cc=-_Cc;  
            if(this->AmpA!=nullptr && _Ca!=Ca){_Ca=Ca; this->AmpA->publish_state(Ca); change_summ=true;}
            if(this->AmpB!=nullptr && _Cb!=Cb){_Cb=Cb; this->AmpB->publish_state(Cb); change_summ=true;}
            if(this->AmpC!=nullptr && _Cc!=Cc){_Cc=Cc; this->AmpC->publish_state(Cc); change_summ=true;}
            if(this->Amps!=nullptr && change_summ){this->Amps->publish_state(Ca+Cb+Cc);}
        }
        void _cbKoef(float Ra, float Rb, float Rc){// будет вызвана при чтении коэфициентов
            static float _Ra=-_Ra;
            static float _Rb=-_Rb;
            static float _Rc=-_Rc;
            if(this->RatioA!=nullptr && _Ra!=Ra){_Ra=Ra; this->RatioA->publish_state(Ra);}
            if(this->RatioB!=nullptr && _Rb!=Rb){_Rb=Rb; this->RatioB->publish_state(Rb);}
            if(this->RatioC!=nullptr && _Rc!=Rc){_Rc=Rc; this->RatioC->publish_state(Rc);}
        }
        void _cbAngles(float Aa, float Ab, float Ac){// будет вызвана при чтении фазовых сдвигов
            static float _Aa=-_Aa;
            static float _Ab=-_Ab;
            static float _Ac=-_Ac;
            // Корректируем углы > 180°, вычитая 360°
            if (Aa > 180) Aa -= 360;
            if (Ab > 180) Ab -= 360;
            if (Ac > 180) Ac -= 360;
            if(this->AngleA!=nullptr && _Aa!=Aa){_Aa=Aa; this->AngleA->publish_state(Aa);}
            if(this->AngleB!=nullptr && _Ab!=Ab){_Ab=Ab; this->AngleB->publish_state(Ab);}
            if(this->AngleC!=nullptr && _Ac!=Ac){_Ac=Ac; this->AngleC->publish_state(Ac);}
        }
        void _cbFreq(float Fr){// будет вызвана когда счетчик ответит на запрос о частоте
            static float _Fr=0;
            if(this->Freq!=nullptr && _Fr!=Fr){_Fr=Fr; this->Freq->publish_state(Fr);}
        }
        void _cbValues_A(float Aa, float Ar){// будет вызвана при получении показаний
            static float _Aa=-_Aa;
            static float _Ar=-_Ar;
            if(this->ValueT1Active!=nullptr && _Aa!=Aa){_Aa=Aa; this->ValueT1Active->publish_state(Aa);}
            if(this->ValueT1Reactive!=nullptr && _Ar!=Ar){_Ar=Ar; this->ValueT1Reactive->publish_state(Ar);}
        }
        void _cbValues_B(float Aa, float Ar){// будет вызвана при получении показаний
            static float _Aa=-_Aa;
            static float _Ar=-_Ar;
            if(this->ValueT2Active!=nullptr && _Aa!=Aa){_Aa=Aa; this->ValueT2Active->publish_state(Aa);}
            if(this->ValueT2Reactive!=nullptr && _Ar!=Ar){_Ar=Ar; this->ValueT2Reactive->publish_state(Ar);}
        }
        void _cbValues_C(float Aa, float Ar){// будет вызвана при получении показаний
            static float _Aa=-_Aa;
            static float _Ar=-_Ar;
            if(this->ValueT3Active!=nullptr && _Aa!=Aa){_Aa=Aa; this->ValueT3Active->publish_state(Aa);}
            if(this->ValueT3Reactive!=nullptr && _Ar!=Ar){_Ar=Ar; this->ValueT3Reactive->publish_state(Ar);}
        }
        void _cbTemp(float T){
            static float _T=-999.0f;
            if(this->Temp!=nullptr && _T!=T){_T=T; this->Temp->publish_state(T);}
        }
        void _cbPhaseEnergyA(float Aa, float Ar){
            static float _Aa=-_Aa; static float _Ar=-_Ar;
            if(this->ValueAA!=nullptr && _Aa!=Aa){_Aa=Aa; this->ValueAA->publish_state(Aa);}
            if(this->ValueRA!=nullptr && _Ar!=Ar){_Ar=Ar; this->ValueRA->publish_state(Ar);}
        }
        void _cbPhaseEnergyB(float Ab, float Rb){
            static float _Ab=-_Ab; static float _Rb=-_Rb;
            if(this->ValueAB!=nullptr && _Ab!=Ab){_Ab=Ab; this->ValueAB->publish_state(Ab);}
            if(this->ValueRB!=nullptr && _Rb!=Rb){_Rb=Rb; this->ValueRB->publish_state(Rb);}
        }
        void _cbPhaseEnergyC(float Ac, float Rc){
            static float _Ac=-_Ac; static float _Rc=-_Rc;
            if(this->ValueAC!=nullptr && _Ac!=Ac){_Ac=Ac; this->ValueAC->publish_state(Ac);}
            if(this->ValueRC!=nullptr && _Rc!=Rc){_Rc=Rc; this->ValueRC->publish_state(Rc);}
        }
        // для трансляции принятого пакета
        void inDataReady(uint8_t size, uint8_t* buff){
           memcpy(inPacket,buff,size);
           sizeInPacket=size;
        }
        // для трансляции отправляемого пакета
        void outDataReady(uint8_t size, uint8_t* buff){
           memcpy(outPacket,buff,size);
           sizeOutPacket=size;
        }

        // разбор полученного пакета
        void parceInbound(){
            if(debugIn){ // показываем буфер для отладки
                outDataReady(fromReadArrow, readBuff);
            }
            if(readBuff[0] == addr || readBuff[0] == 0){ // только если ответ от нашего счетчика
                uint32_t temp;
                if(fromReadArrow == 4){ // 4 байта скорее всего это пакет подтверждение
                    lastError=(_replyReason)readBuff[1];
                    ESP_LOGD("Mercury", "Response code: %d, request type: %d", lastError, forSenfType);
                    // Сбрасываем цикл только для ошибок авторизации/канала связи.
                    // ERROR_COMMAND(1) и ERROR_HARDWARE(2) — счётчик не поддерживает запрос,
                    // не нужно переинициализировать соединение.
                    if(lastError == ERROR_ACCESS_LEVEL || lastError == ERROR_CONNECTION){
                        procError=true;
                        // При ошибке авторизации пробуем следующий пароль
                        if(lastError == ERROR_ACCESS_LEVEL && password_attempt < 2){
                            password_attempt++;
                            ESP_LOGW("Mercury", "Auth failed (code %d), trying next password", lastError);
                        } else if(lastError == ERROR_ACCESS_LEVEL){
                            ESP_LOGE("Mercury", "All password attempts failed!");
                        } else if(lastError == ERROR_CONNECTION){
                            ESP_LOGW("Mercury", "Connection error (code %d) on request type %d", lastError, forSenfType);
                        }
                    } else {
                        // Успешная авторизация - запоминаем рабочий пароль
                        if(forSenfType == GET_ACCESS && lastError == REP_OK){
                            ESP_LOGI("Mercury", "Authentication successful with attempt %d", password_attempt);
                        }
                    }
                    if(readBuff[0] == 0){
                        lastError=(_replyReason)(readBuff[1] | 0x80);// те же ошибки с флагом широковещалки
                    }
                    fromReadArrow=0;
                } else if(fromReadArrow == 5){ // 5 байтовый входящий
                    if(forSenfType == GET_ADDR){
                        addr=readBuff[2]; // ответ на запрос сетевого адреса
                        fromReadArrow=0;
                        lastError=REP_OK;
                    } else if(forSenfType == GET_TEMP){ // ответ на запрос температуры (NcT int16 LE / 100 = °C)
                        fromReadArrow=0;
                        lastError=REP_OK;
                        int16_t nct = (int16_t)(readBuff[1] | ((uint16_t)readBuff[2] << 8));
                        _cbTemp(nct / 100.0f);
                    }
                } else if(fromReadArrow == 15){ // пакет 4x3 или 3x4
                    if(forSenfType == GET_POWER){ // ответ на запрос мощности
                        fromReadArrow=0;
                        lastError=REP_OK;              
                        _cbPower((float)dm32_3(readBuff+1)/100, 
                                (float)dm32_3(readBuff+4)/100,
                                (float)dm32_3(readBuff+7)/100,
                                (float)dm32_3(readBuff+10)/100);
                    }
                } else if(fromReadArrow == 12){ // пакет 3x3
                    if(forSenfType == GET_VOLTAGE){ // ответ на запрос напряжения
                        fromReadArrow=0;
                        lastError=REP_OK;
                        _cbVolt((float)dm32_3(readBuff+1)/100, 
                                (float)dm32_3(readBuff+4)/100,
                                (float)dm32_3(readBuff+7)/100);
                    } else if (forSenfType == GET_KOEF_POWER){ // ответ на запрос коэфициентов
                        fromReadArrow=0;
                        lastError=REP_OK;
                        _cbKoef((float)dm32_3(readBuff+1)/1000, 
                                (float)dm32_3(readBuff+4)/1000,
                                (float)dm32_3(readBuff+7)/1000);
                    } else if (forSenfType == GET_ANGLE_PH){ // ответ на запрос углов
                        fromReadArrow=0;
                        lastError=REP_OK;
                        _cbAngles((float)dm32_3(readBuff+1)/100, 
                                (float)dm32_3(readBuff+4)/100,
                                (float)dm32_3(readBuff+7)/100);
                    } else if (forSenfType == GET_CURRENT){ // ответ на запрос тока
                        fromReadArrow=0;
                        lastError=REP_OK;
                        _cbCurrent((float)dm32_3(readBuff+1)/1000, 
                                (float)dm32_3(readBuff+4)/1000,
                                (float)dm32_3(readBuff+7)/1000);
                    }
                } else if (fromReadArrow == 6){ // 6 байт 
                    if (forSenfType == GET_FREQ){ // ответ на запрос частоты
                        fromReadArrow=0;
                        lastError=REP_OK;
                        _cbFreq((float)dm32_3(readBuff+1)/100);
                    } else if (forSenfType == GET_TEMP){ // ответ на запрос температуры
                        fromReadArrow=0;
                        lastError=REP_OK;
                        _cbTemp((int8_t)readBuff[1]);
                    }
                } else if (fromReadArrow == 19){ // 19 байт
                    if (forSenfType == GET_VERS){
                        char temp[15]={0};
                        // получаем серийный номер
                        if(this->sn_string!=nullptr){ //серийный номер
                            snprintf(temp, sizeof(temp)-1, "%02d%02d%02d%02d",readBuff[1],readBuff[2],readBuff[3],readBuff[4]);
                            this->sn_string->publish_state(temp);
                        }
                        if(this->vers_string!=nullptr){ //версия прибора
                            snprintf(temp, sizeof(temp)-1, "%d.%02d.%02d",readBuff[8],readBuff[9],readBuff[10]);
                            this->vers_string->publish_state(temp);
                        }
                        if(this->fab_date_string!=nullptr){ //дата изготовления
                            snprintf(temp, sizeof(temp)-1, "%d/%02d/%02d",readBuff[5],readBuff[6],readBuff[7]);
                            this->fab_date_string->publish_state(temp);
                        }
                        fromReadArrow=0;
                        lastError=REP_OK;
                    } else if (forSenfType == GET_VALUE_A){
                        fromReadArrow=0; lastError=REP_OK;
                        _cbValues_A((float)dm32_4(readBuff+1)/1000, (float)dm32_4(readBuff+9)/1000);
                    } else if (forSenfType == GET_VALUE_B){
                        fromReadArrow=0; lastError=REP_OK;
                        _cbValues_B((float)dm32_4(readBuff+1)/1000, (float)dm32_4(readBuff+9)/1000);
                    } else if (forSenfType == GET_VALUE_C){
                        fromReadArrow=0; lastError=REP_OK;
                        _cbValues_C((float)dm32_4(readBuff+1)/1000, (float)dm32_4(readBuff+9)/1000);
                    } else if (forSenfType == GET_PHASE_ENERGY_A){
                        fromReadArrow=0; lastError=REP_OK;
                        _cbPhaseEnergyA((float)dm32_4(readBuff+1)/1000, (float)dm32_4(readBuff+9)/1000);
                    } else if (forSenfType == GET_PHASE_ENERGY_B){
                        fromReadArrow=0; lastError=REP_OK;
                        _cbPhaseEnergyB((float)dm32_4(readBuff+1)/1000, (float)dm32_4(readBuff+9)/1000);
                    } else if (forSenfType == GET_PHASE_ENERGY_C){
                        fromReadArrow=0; lastError=REP_OK;
                        _cbPhaseEnergyC((float)dm32_4(readBuff+1)/1000, (float)dm32_4(readBuff+9)/1000);
                    }
                } else if (fromReadArrow == 17){ //17 байт
                    //...
                }
            } else { // данные чужого счетчика
                fromReadArrow=0; // сбрасываем данные  
                lastError=REP_OK;
            }
        }

        void setupMerc(uint32_t _scanPeriod){ // установка начальных параметров
            scanPeriod = _scanPeriod; // корректировка на время обработки
            scanTimer = millis() - _scanPeriod; // инициализация таймера опроса
        }

        void setUpdatePeriod(uint32_t period){ // изменение периода на лету
            if(period < MIN_SCAN_PERIOD){period = MIN_SCAN_PERIOD;}
            scanPeriod = period;
        }

        // коннектор исходящих данных
        // проверка наличия данных для отправки, за одно цикл обработки
        uint8_t availableMerc(){
            uint32_t _now=millis();
            static uint8_t counter=0;

            // КОНТРОЛЬ НЕ ОТВЕТА
            if(waiteReply && _now-timeReadByte>ABORT_RECIVE_TIME){ // отслеживаем таймаут приема байта
                waiteReply = false; 
                if(counter>5){ // поднимаем ошибки только на запросах данных
                    lastError=ERROR_TIMEOUT;
                }
                procError=true;  // поднимаем ошибку для повтора цикла инициализации
            }
   
            // если в буфере есть данные - показать их количесто
            uint8_t ret=forSendSize-forSendArrow;
            if(ret){ // если есть данные для отправки
                return ret; //ничего не делаем
            } 
    
            // ЦИКЛ ОБРАБОТКИ
            if(_now-scanTimer>=scanPeriod){ // таймер шиклов опроса  
                if(!waiteReply && _now-timeSendByte>=PACKET_MIN_DELAY){  // ТАЙМЕР МЕЖПАкЕТНОГО ИНТРЕВАЛА, одновременно ждем ответ
                    timeSendByte=_now;
                    while(counter<=14){
                        if      (counter==0){sConnect(); break;} // на нулевом шаге пожимаем руку
                        else if (counter==1){sAccess(); break;}  // далее просим доступ
                        // поиск адреса только если он нулевой и пока не найдем дальше не работаем
                        else if (counter==2 && addr==0){sGetAddr(); counter=15; procError=true; break;} 
                        else if (counter==3){sGetVers(); break;}     // далее версию, дату изготовления, серийник
                        else if (counter==4){if(cbValuesA){sGetValue_A();  break;}}   // тариф T1
                        else if (counter==5){if(cbValuesB){sGetValue_B();  break;}}   // тариф T2
                        else if (counter==6){if(cbValuesC){sGetValue_C();  break;}}   // тариф T3
                        else if (counter==7){if(cbPower){sGetPower(); break;}}     // мощность
                        else if (counter==8){if(cbVolt){sGetVoltage(); break;}}    // напряжение
                        else if (counter==9){if(cbCurrent){sGetCurrent(); break;}} // ток
                        else if (counter==10){if(cbKoef){sGetKoefPower(); break;}}  // коэфициенты
                        else if (counter==11){if(cbAngles){sGetAnglePh(); break;}}  // углы
                        else if (counter==12){if(cbFreq){sGetFreq(); break;}}      // частота
                        else if (counter==13){if(cbTemp){sGetTemp(); break;}}       // температура
                        else if (counter==14){if(cbPhaseEnergy){sGetPhaseEnergyA(); break;}} // фаза A
                        else if (counter==15){if(cbPhaseEnergy){sGetPhaseEnergyB(); break;}} // фаза B
                        else if (counter==16){if(cbPhaseEnergy){sGetPhaseEnergyC(); break;}} // фаза C
                        counter++;
                    }
                    if(counter++>16){ // зацикливание счетчика
                        if(_now-scanTimer>2*scanPeriod){ // еСЛИ ВРЕМЯ ПЕРИОДА прешышает требуемое значительно
                            scanTimer=_now; // то сбрасываем таймер - пофиг регулярность
                        } else {
                            scanTimer+=scanPeriod; // так мы учитываем уже отработанное время точно
                        }
                        if(procError){ // если в цикле была ошибка при связи
                            procError=false;
                            counter=0;  // пройдем весь цикл запросов, возможно снова нужна авторизация
                        } else {
                            counter=3; // если без ошибок, то повторной инициализации не нужно, просто опросим параметры
                            password_attempt=0; // Сбрасываем счетчик попыток при успешном цикле
                        }
                    }
                }
            } else {
                timeReadByte=_now; // для сброса ложной ошибки таймаута получения ответа
            }
            return forSendSize-forSendArrow; // возможно в буфере появились данные
        }

        //отдача байта счетчику
        uint8_t getByteForMerc(){
            if(forSendSize-forSendArrow){ //если буфер не пустой 
                waiteReply = true; 
                uint8_t ret=sendBuff[forSendArrow++];
                if(forSendSize-forSendArrow==0){
                    forSendSize=0;
                    forSendArrow=0;
                }
                return ret;  
            }
            return 0;
        }

        //отдача буфера счетчику
        uint8_t* getBuffForMerc(){
            uint8_t* ret= &(sendBuff[forSendArrow]);
            forSendArrow=0;
            forSendSize=0;
            return ret;
        }

        // входящий байт пихаем сюда
        _replyReason getFromMerc(uint8_t d){
            uint32_t _now=millis();
            if(_now-timeReadByte>ABORT_RECIVE_TIME){ // таймаут получения данных
                goto reset_buff;  //ошибку не поднимаем, нужно только для корректности данных
            } 
            if(fromReadArrow == sizeof(readBuff)){ // переполнение буфера
                procError=true;  // поднимаем ошибку для повтора цикла инициализации
                lastError = BUFFER_OVERFLOW;
        reset_buff:   
                fromReadArrow=0;  // сбрасываем уже не нужные данные
            }
            waiteReply = false; // снимаем флаг ожидания ответа, что то получили
            timeReadByte=_now; // засекаем время получения байта
            readBuff[fromReadArrow++]=d; // кладем байт в буфер
            if(fromReadArrow==1){ // если это начало пакета
                stepCrc16mb(d, true); // начнем счикать КС
            } else if( fromReadArrow <3){ // размер данных еще не достаточен для КС + данные
                stepCrc16mb(d);
            } else { // если получили пакет больше 2 байт+CS
                if(stepCrc16mb(d) == 0){ //вероятный конец данных контрольная сумма обнулилась !!!
                    parceInbound();
                    availableMerc(); // обслужить буфер для очистки
                }
            }
            return lastError;
        }

#endif //MERCURY230_PROTO_H
