/*
 * ledController.h
 *
 *  Created on: 25 Jul 2016
 *      Author: steve
 */

#ifndef LEDBUZZERCONTROLLER_H_
#define LEDBUZZERCONTROLLER_H_

int initialise_leds();

int initialise_buzzer();

void buzzer_terminate();

void disable_bar();

void enable_running_led(void);

void emvSuccessTone(void);

void emvAlertTone(void);

void startup_visualization(void);

void emvSuccessVisualization();

void visualization_mifare_classic(int *tag, int *new_tag);

void visualization_mifare_plus(int *tag, int *new_tag);

void visualization_mifare_ultralight(int *tag, int *new_tag);

void visualization_mifare_desfire(int *tag, int *new_tag);

void visualization_girogo();

void visualization_cipurse(int *tag, int *new_tag);

void visualization_iso14443a(int *tag, int *new_tag);

void visualization_iso14443b(int *tag, int *new_tag);

void visualization_jewel(int *tag, int *new_tag);

void visualization_felica(int *tag, int *new_tag);



#endif /* LEDBUZZERCONTROLLER_H_ */
