
#include "ledBuzzerController.h"

#include <feig/leds.h>
#include <feig/buzzer.h>
#include "macros.h"

int initialise_leds()
{
	return leds_init();
}

int initialise_buzzer()
{
	return buzzer_init();
}

void buzzer_terminate()
{
	return buzzer_term();
}

void disable_bar()
{
	leds_off(LEDS_GREEN1 | LEDS_GREEN2 | LEDS_GREEN3 |
		 LEDS_YELLOW | LEDS_RED);
}

void enable_running_led(void)
{
	leds_on(LEDS_GREEN0);
}

void emvSuccessTone(void)
{
	/* EMVCo success tone.
	* Buzzer Beep @ 1500Hz for 500ms
	*/
	buzzer_beep(1500, 500);
}

void emvAlertTone(void)
{
	/* EMVCo alert tone.
	 * Buzzer Beep @ 750Hz for 200ms
	 * [On -> Off -> On]
	 */
	buzzer_beep(750, 200);
	usleep(200000);
	buzzer_beep(750, 200);
}

void startup_visualization(void)
{
	/* Enable logo leds */
	leds_on(LEDS_LOGO0 | LEDS_LOGO1);

	leds_on(LEDS_GREEN1);

	usleep(100000);

	leds_on(LEDS_YELLOW);

	usleep(100000);

	leds_on(LEDS_RED);

	usleep(100000);

	leds_off(LEDS_GREEN1 | LEDS_YELLOW | LEDS_RED);

	buzzer_beep(659, 150);
	buzzer_beep(740, 150);
	buzzer_beep(830, 150);
	buzzer_beep(987, 300);
}

void emvSuccessVisualization(int *tag, int *new_tag)
{
	if ((*tag) && (*new_tag)) {

		leds_off(LEDS_GREEN1 | LEDS_GREEN2 | LEDS_GREEN3 |
			 LEDS_YELLOW | LEDS_RED);
		leds_on(LEDS_GREEN1);
		usleep(100000);
		leds_on(LEDS_GREEN2);
		usleep(100000);
		leds_on(LEDS_GREEN3);
		emvSuccessTone();
		usleep(300000);
		*new_tag = 0;
		*tag = 0;
	}
}

void visualization_mifare_classic(int *tag, int *new_tag)
{
	if ((*tag) && (*new_tag)) {
		buzzer_on(1500);
		leds_off(LEDS_GREEN1 | LEDS_GREEN2 | LEDS_GREEN3 |
			 LEDS_YELLOW | LEDS_RED);
		usleep(100000);
		usleep(100000);
		leds_on(LEDS_RED);
		buzzer_off();
		*new_tag = 0;
		*tag = 0;
	}
}

void visualization_mifare_plus(int *tag, int *new_tag)
{
	if ((*tag) && (*new_tag)) {
		buzzer_on(1500);
		leds_off(LEDS_GREEN1 | LEDS_GREEN2 | LEDS_GREEN3 |
			 LEDS_YELLOW | LEDS_RED);
		usleep(100000);
		leds_on(LEDS_GREEN2);
		usleep(100000);
		leds_on(LEDS_RED);
		buzzer_off();
		*new_tag = 0;
		*tag = 0;
	}
}

void visualization_mifare_ultralight(int *tag, int *new_tag)
{
	if ((*tag) && (*new_tag)) {
		buzzer_on(1500);
		leds_off(LEDS_GREEN1 | LEDS_GREEN2 | LEDS_GREEN3 |
			 LEDS_YELLOW | LEDS_RED);
		usleep(100000);
		leds_on(LEDS_GREEN1);
		usleep(100000);
		leds_on(LEDS_RED);
		buzzer_off();
		*new_tag = 0;
		*tag = 0;
	}
}

void visualization_mifare_desfire(int *tag, int *new_tag)
{
	if ((*tag) && (*new_tag)) {
		buzzer_on(1500);
		leds_off(LEDS_GREEN1 | LEDS_GREEN2 | LEDS_GREEN3 |
			 LEDS_YELLOW | LEDS_RED);
		leds_on(LEDS_GREEN1);
		usleep(100000);
		leds_on(LEDS_GREEN2);
		usleep(100000);
		leds_on(LEDS_RED);
		buzzer_off();
		*new_tag = 0;
		*tag = 0;
	}
}

void visualization_girogo(int *tag, int *new_tag)
{
	if ((*tag) && (*new_tag)) {
		buzzer_on(1500);
		leds_off(LEDS_GREEN1 | LEDS_GREEN2 | LEDS_GREEN3 |
			 LEDS_YELLOW | LEDS_RED);
		usleep(100000);
		leds_on(LEDS_GREEN2);
		usleep(100000);
		buzzer_off();
		*new_tag = 0;
		*tag = 0;
	}
}



void visualization_cipurse(int *tag, int *new_tag)
{
	if ((*tag) && (*new_tag)) {
		buzzer_on(1500);
		leds_off(LEDS_GREEN1 | LEDS_GREEN2 | LEDS_GREEN3 |
			 LEDS_YELLOW | LEDS_RED);
		usleep(100000);
		leds_on(LEDS_YELLOW | LEDS_RED);
		usleep(100000);
		buzzer_off();
		*new_tag = 0;
		*tag = 0;
	}
}

void visualization_iso14443a(int *tag, int *new_tag)
{
	if ((*tag) && (*new_tag)) {
		buzzer_on(1500);
		leds_off(LEDS_GREEN1 | LEDS_GREEN2 | LEDS_GREEN3 |
			 LEDS_YELLOW | LEDS_RED);
		leds_on(LEDS_GREEN1);
		usleep(100000);
		leds_on(LEDS_YELLOW);
		usleep(100000);
		leds_on(LEDS_RED);
		buzzer_off();
		*new_tag = 0;
		*tag = 0;
	}
}

void visualization_iso14443b(int *tag, int *new_tag)
{
	if ((*tag) && (*new_tag)) {
		buzzer_on(1500);
		leds_off(LEDS_GREEN1 | LEDS_GREEN2 | LEDS_GREEN3 |
			 LEDS_YELLOW | LEDS_RED);
		leds_on(LEDS_GREEN1);
		usleep(100000);
		leds_on(LEDS_YELLOW);
		usleep(100000);
		buzzer_off();
		*new_tag = 0;
		*tag = 0;
	}
}

void visualization_jewel(int *tag, int *new_tag)
{
	if ((*tag) && (*new_tag)) {
		buzzer_on(1500);
		leds_off(LEDS_GREEN1 | LEDS_GREEN2 | LEDS_GREEN3 |
			 LEDS_YELLOW | LEDS_RED);
		usleep(100000);
		usleep(100000);
		leds_on(LEDS_GREEN3);
		buzzer_off();
		*new_tag = 0;
		*tag = 0;
	}
}

void visualization_felica(int *tag, int *new_tag)
{
	if ((*tag) && (*new_tag)) {
		buzzer_on(1500);
		leds_off(LEDS_GREEN1 | LEDS_GREEN2 | LEDS_GREEN3 |
			 LEDS_YELLOW | LEDS_RED);
		usleep(100000);
		leds_on(LEDS_YELLOW);
		usleep(100000);
		buzzer_off();
		*new_tag = 0;
		*tag = 0;
	}
}
