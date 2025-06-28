#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Парсер отчетов сканера Nessus
Извлекает CVE, Risk, Host, Protocol, Port, Name, Synopsis, Description, CVSS 3.0, Solution
"""

import csv
import sys
import os
import argparse

def parse_nessus_csv(input_file, output_file):
    """Парсит CSV файл Nessus и создает отчет"""
    
    # Проверяем существование входного файла
    if not os.path.exists(input_file):
        print(f"Ошибка: Файл {input_file} не найден!")
        return False
    
    try:
        with open(input_file, 'r', encoding='utf-8') as csvfile:
            # Читаем CSV файл
            reader = csv.DictReader(csvfile)
            
            # Открываем файл для записи результата
            with open(output_file, 'w', encoding='utf-8') as outfile:
                outfile.write("NESSUS SCANNER REPORT\n")
                outfile.write("=" * 50 + "\n\n")
                
                # Счетчики для статистики
                total_vulnerabilities = 0
                risk_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'None': 0}
                
                for row_num, row in enumerate(reader, 1):
                    # Извлекаем нужные поля
                    cve = row.get('CVE', '').strip()
                    risk = row.get('Risk', '').strip()
                    host = row.get('Host', '').strip()
                    protocol = row.get('Protocol', '').strip()
                    port = row.get('Port', '').strip()
                    name = row.get('Name', '').strip()
                    synopsis = row.get('Synopsis', '').strip()
                    description = row.get('Description', '').strip()
                    solution = row.get('Solution', '').strip()
                    cvss_30 = row.get('CVSS v3.0 Base Score', '').strip()
                    
                    # Пропускаем записи без уязвимостей (Risk = None)
                    if risk == 'None' or not risk:
                        continue
                    
                    # Увеличиваем счетчики
                    total_vulnerabilities += 1
                    if risk in risk_counts:
                        risk_counts[risk] += 1
                    
                    # Записываем информацию об уязвимости
                    outfile.write(f"VULNERABILITY #{total_vulnerabilities}\n")
                    outfile.write("-" * 30 + "\n")
                    
                    # CVE
                    if cve:
                        outfile.write(f"CVE: {cve}\n")
                    
                    # Risk (уровень риска)
                    if risk:
                        outfile.write(f"Risk Level: {risk}\n")
                    
                    # Host
                    if host:
                        outfile.write(f"Host: {host}\n")
                    
                    # Protocol и Port
                    if protocol and port:
                        outfile.write(f"Protocol/Port: {protocol}/{port}\n")
                    
                    # Name
                    if name:
                        outfile.write(f"Name: {name}\n")
                    
                    # Synopsis
                    if synopsis:
                        outfile.write(f"Synopsis: {synopsis}\n")
                    
                    # Description
                    if description:
                        outfile.write(f"Description: {description}\n")
                    
                    # Solution
                    if solution:
                        outfile.write(f"Solution: {solution}\n")
                    
                    # CVSS 3.0
                    if cvss_30:
                        outfile.write(f"CVSS 3.0: {cvss_30}\n")
                    
                    outfile.write("\n" + "=" * 50 + "\n\n")
                    
                    # Показываем прогресс каждые 10 записей
                    if total_vulnerabilities % 10 == 0:
                        print(f"Обработано уязвимостей: {total_vulnerabilities}")
                
                # Записываем итоговую статистику
                outfile.write("FINAL STATISTICS\n")
                outfile.write("=" * 30 + "\n")
                outfile.write(f"Total vulnerabilities: {total_vulnerabilities}\n\n")
                
                outfile.write("Risk level distribution:\n")
                for risk_level, count in risk_counts.items():
                    if count > 0:
                        outfile.write(f"  {risk_level}: {count}\n")
                
                print(f"\nОбработка завершена!")
                print(f"Всего найдено уязвимостей: {total_vulnerabilities}")
                print(f"Результат сохранен в файл: {output_file}")
                
                return True
                
    except Exception as e:
        print(f"Ошибка при обработке файла: {e}")
        return False

def main():
    """Основная функция программы"""
    parser = argparse.ArgumentParser(description='Парсер отчетов сканера Nessus')
    parser.add_argument('input_file', help='Путь к входному CSV файлу')
    parser.add_argument('-o', '--output', default='nessus_report.txt', 
                       help='Путь к выходному файлу (по умолчанию: nessus_report.txt)')
    
    args = parser.parse_args()
    
    print("Парсер отчетов сканера Nessus")
    print("=" * 40)
    print(f"Входной файл: {args.input_file}")
    print(f"Выходной файл: {args.output}")
    print()
    
    # Запускаем парсинг
    success = parse_nessus_csv(args.input_file, args.output)
    
    if success:
        print("\nПрограмма завершена успешно!")
    else:
        print("\nПрограмма завершена с ошибками!")
        sys.exit(1)

if __name__ == "__main__":
    main() 