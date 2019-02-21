#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "tz.h"

/* This table is from https://msdn.microsoft.com/en-us/library/ms912391(v=winembedded.11).aspx,
 * we should update this table from the site regularly */
static struct tz {
	const char *location, *string, *location_cli;
} tz_db[] = {
	{ "International Date Line West",	"GMT12", "Pacific/Wallis" },
	{ "Midway Island, Samoa",	"GMT11", "Pacific/Midway" },
	{ "Hawaii",	"GMT10", "Pacific/Honolulu" },
	{ "Alaska",	"GMT9", "America/Anchorage" },
	{ "Pacific Time, Tijuana",	"GMT8", "America/Tijuana" },
	{ "Mountain Time",	"GMT7", "America/Denver" },
	{ "Chihuahua, La Paz, Mazatlan",	"GMT7", "America/Chihuahua" },
	{ "Arizona",	"GMT7" , "America/Phoenix"},
	{ "Central Time",	"GMT6", "America/Belize"},
	{ "Saskatchewan",	"GMT6", "Canada/Saskatchewan" },
	{ "Guadalajara, Mexico City, Monterrey",	"GMT6", "America/Mexico_City" },
	{ "Central America",	"GMT6", "America/Guatemala" },
	{ "Eastern Time",	"GMT5", "America/Cayman" },
	{ "Indiana",	"GMT5", "America/Indianapolis" },
	{ "Bogota, Lima, Quito",	"GMT5", "America/Lima" },
	{ "Atlantic Time",	"GMT4", "Canada/Atlantic" },
	{ "Caracas, La Paz",	"GMT4", "America/Caracas" },
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	{ "Santiago",	"GMT4", "America/Santiago" },
#else
	{ "Santiago",	"GMT-4", "America/Santiago" },
#endif
	{ "Newfoundland and Labrador",	"GMT3:30", "Canada/Newfoundland" },
	{ "Brasilia",	"GMT3", "Brazil/East" },
	{ "Buenos Aires, Georgetown",	"GMT3", "America/Buenos_Aires" },
	{ "Greenland",	"GMT3", "America/Buenos_Aires" },
	{ "Mid-Atlantic",	"GMT2", "Atlantic/South_Georgia" },
	{ "Azores",	"GMT1", "Atlantic/Azores" },
	{ "Cape Verde Islands",	"GMT1", "Atlantic/Cape Verde" },
	{ "Greenwich Mean Time: Dublin, Edinburgh, Lisbon, London",	"GMT0", "Europe/Dublin" },
	{ "Casablanca, Monrovia",	"GMT0", "Africa/Casablanca" },
	{ "Belgrade, Bratislava, Budapest, Ljubljana, Prague",	"GMT-1", "Europe/Belgrade" },
	{ "Sarajevo, Skopje, Warsaw, Zagreb",	"GMT-1", "Europe/Sarajevo" },
	{ "Brussels, Copenhagen, Madrid, Paris",	"GMT-1", "Europe/Brussels" },
	{ "Amsterdam, Berlin, Bern, Rome, Stockholm, Vienna",	"GMT-1", "Europe/Amsterdam" },
	{ "West Central Africa",	"GMT-1", "Africa/Bangui" },
	{ "Bucharest",	"GMT-2", "Europe/Bucharest" },
	{ "Cairo",	"GMT-2", "Africa/Cairo" },
	{ "Helsinki, Kiev, Riga, Sofia, Tallinn, Vilnius",	"GMT-2", "Europe/Helsinki" },
	{ "Athens, Istanbul, Minsk",	"GMT-2", "Europe/Athens" },
	{ "Jerusalem",	"GMT-2", "Israel" },
	{ "Harare, Pretoria",	"GMT-2", "Africa/Harare" },
	{ "Moscow, St. Petersburg, Volgograd",	"GMT-3", "Europe/Moscow" },
	{ "Kuwait, Riyadh",	"GMT-3", "Asia/Kuwait" },
	{ "Nairobi",	"GMT-3", "Africa/Nairobi" },
	{ "Baghdad",	"GMT-3", "Asia/Baghdad" },
	{ "Tehran",	"GMT-3:30", "Asia/Tehran" },
	{ "Abu Dhabi, Muscat",	"GMT-4", "Asia/Muscat" },
	{ "Baku, Tbilisi, Yerevan",	"GMT-4", "Asia/Baku" },
	{ "Kabul",	"GMT-4:30", "Asia/Kabul" },
	{ "Ekaterinburg",	"GMT-5", "Asia/Yekaterinburg" },
	{ "Islamabad, Karachi, Tashkent",	"GMT-5", "Asia/Karachi" },
	{ "Chennai, Kolkata, Mumbai, New Delhi",	"GMT-5:30", "Asia/Kolkata" },
	{ "Kathmandu",	"GMT-5:45", "Asia/Kathmandu" },
	{ "Astana, Dhaka",	"GMT-6", "Asia/Dhaka" },
	{ "Sri Jayawardenepura",	"GMT-6", "Asia/Dhaka" },
	{ "Almaty, Novosibirsk",	"GMT-6", "Asia/Almaty" },
	{ "Yangon Rangoon",	"GMT-6:30", "Asia/Rangoon" },
	{ "Bangkok, Hanoi, Jakarta",	"GMT-7", "Asia/Bangkok" },
	{ "Krasnoyarsk",	"GMT-7", "Asia/Krasnoyarsk" },
	{ "Beijing, Chongqing, Hong Kong, Urumqi",	"GMT-8", "Asia/Chongqing" },
	{ "Kuala Lumpur, Singapore",	"GMT-8", "Asia/Kuala Lumpur" },
	{ "Taipei",	"GMT-8", "Asia/Taipei" },
	{ "Perth",	"GMT-8", "Australia/Perth" },
	{ "Irkutsk, Ulaanbaatar",	"GMT-8", "Asia/Irkutsk" },
	{ "Seoul",	"GMT-9", "Asia/Seoul" },
	{ "Osaka, Sapporo, Tokyo",	"GMT-9", "Asia/Tokyo" },
	{ "Yakutsk",	"GMT-9", "Asia/Yakutsk" },
	{ "Darwin",	"GMT-9:30", "Australia/Darwin" },
	{ "Adelaide",	"GMT-9:30", "Australia/Adelaide" },
	{ "Canberra, Melbourne, Sydney",	"GMT-10", "Australia/Melbourne" },
	{ "Brisbane",	"GMT-10", "Australia/Brisbane" },
	{ "Hobart",	"GMT-10", "Australia/Hobart" },
	{ "Vladivostok",	"GMT-10", "Asia/Vladivostok" },
	{ "Guam, Port Moresby",	"GMT-10", "Pacific/Guam" },
#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	{ "Solomon Is., New Caledonia",	"GMT-11", "Pacific/Guadalcanal" },
#endif
	{ "Magadan, Solomon Islands, New Caledonia",	"GMT-11", "Asia/Magadan" },
	{ "Fiji Islands, Kamchatka, Marshall Islands",	"GMT-12", "Pacific/Fiji" },
	{ "Auckland, Wellington",	"GMT-12", "Pacific/Auckland" },
};

const size_t nr_tz = sizeof(tz_db) / sizeof(tz_db[0]);

const char *get_tz_utc_offset(unsigned int index)
{
	static char utc_offset[16];
	char *ret, *endptr, hour;
	unsigned char minute;

	if (index >= nr_tz)
		return "";

	ret = strpbrk(tz_db[index].string, "+-0123456789");
	if (ret) {
		hour = strtol(ret, &endptr, 10);
		minute = (endptr && *endptr == ':') ? strtoul(endptr + 1, NULL, 10) : 0;
	} else {
		hour = minute = 0;
	}

#if defined(CONFIG_CMCC) || defined(CONFIG_CU)
	if(hour==0)
		memset(utc_offset, '\0', sizeof(utc_offset));
	else
		snprintf(utc_offset, sizeof(utc_offset), "%+03hhd:%02hhu", -hour, minute);
#else
	snprintf(utc_offset, sizeof(utc_offset), "%+03hhd:%02hhu", -hour, minute);
#endif

	return utc_offset;
}

const char *get_tz_string(unsigned int index, unsigned char dst_enabled)
{
	static char tz_string[16];
	char *ret;

	if (index >= nr_tz)
		return "";

	if (dst_enabled) {
		return tz_db[index].string;
	} else {
		ret = strpbrk(tz_db[index].string, "+-0123456789");
		if (ret)
			ret = strpbrk(ret, "ABCDEFGHIJKLMNOPQRSTUVWXYZ");

		if (ret) {
			memset(tz_string, 0, sizeof(tz_string));
			strncpy(tz_string, tz_db[index].string, ret - tz_db[index].string);

			return tz_string;
		} else {
			/* No DST information in dst_string */
			return tz_db[index].string;
		}
	}
}

const char *get_tz_location(unsigned int index)
{
	if (index >= nr_tz)
		return "";

	return tz_db[index].location;
}

const char *get_tz_location_cli(unsigned int index)
{
	if (index >= nr_tz)
		return "";

	return tz_db[index].location_cli;
}

#ifndef __UCLIBC__ //__GLIBC__
int is_tz_dst_exist(unsigned int index)
{
	char *ret;
	
	if (index >= nr_tz)
		return 0;
	
	ret = strpbrk(tz_db[index].string, "+-0123456789");
	
	if (ret) {
		ret = strpbrk(ret, "ABCDEFGHIJKLMNOPQRSTUVWXYZ");

		if (ret) 
			return 1;
	}

	return 0;
}

void format_tz_location(char * location)
{
	if (!location) {
		fprintf(stderr, "[Error] TZ location is Null!");
		return;
	}

	while(*location != 0)
	{
		if(*location == ' ')
			*location = '_';
		
		location++;
	}
	return;
}

const char *get_format_tz_utc_offset(unsigned int index)
{
	static char utc_offset[16];
	char *ret, *endptr, hour;
	unsigned char minute;

	if (index >= nr_tz)
		return "";

	ret = strpbrk(tz_db[index].string, "+-0123456789");
	if (ret) {
		hour = strtol(ret, &endptr, 10);
		minute = (endptr && *endptr == ':') ? strtoul(endptr + 1, NULL, 10) : 0;
	} else {
		hour = minute = 0;
	}
	
	if(minute)
		snprintf(utc_offset, sizeof(utc_offset), "%c%d:%d",hour>0?'+':'-',hour>0?hour:-hour,minute);
	else
		snprintf(utc_offset, sizeof(utc_offset), "%c%d",hour>0?'+':'-',hour>0?hour:-hour);
	
	return utc_offset;
}
#endif // of __GLIBC__
