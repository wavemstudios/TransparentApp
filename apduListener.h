/*
 * apduListener.h
 *
 *  Created on: 10 Oct 2016
 *      Author: steve
 */

#ifndef APDULISTENER_H_
#define APDULISTENER_H_

int socketInitialise();
int socketRead(int fd, union tech_data *tech_data);
int socketWrite();

#endif /* APDULISTENER_H_ */
