/**
\file
\brief Заголовочный файл с описанием классов
Данный файл содержит в себе определения основных
структур и функций, используемых в программе
*/


#pragma once

#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <array>
#include <algorithm>
#include <utility>
#include <memory>
#include "protocol.h"


/**
 * @brief Основной класс.
 * метод parse принимает данные по указателю и длинне и разделяет на уровни L2, L3. L4.
 *
 */
class Packet {
    std::shared_ptr<Protocol> _l2;
    std::shared_ptr<Protocol> _l3;
    std::shared_ptr<Protocol> _l4;

   // byte _l3_version;
    byte _l4_type;

    Packet(const Packet& p) = delete;
    Packet& operator=(const Packet& p) = delete;

public:
    Packet() = default;
    /**
     * @brief  метод parse принимает данные по указателю и длинне и разделяет на уровни L2, L3. L4.  .
     *
     */
    void parse(unsigned char* d, std::size_t lenght);

    /**
     * @brief  метод L2 возвращает объект протокола второго уровня по указателю на базовый класс Protocol.
     *
     */
    std::shared_ptr<Protocol> l2() const;
    /**
     * @brief  метод L3 возвращает объект протокола второго уровня по указателю на базовый класс Protocol.
     *
     */
    std::shared_ptr<Protocol> l3() const;
    /**
     * @brief  метод L4 возвращает объект протокола второго уровня по указателю на базовый класс Protocol.
     *
     */
    std::shared_ptr<Protocol> l4() const;

};
