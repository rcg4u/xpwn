#!/bin/bash
SIZE=`du -m $1 | cut -f1`
if [ $SIZE -le 32 ]
then
	FILEPATH=`echo $1 | sed "s/ipsw\\///"`
	NONCE=`./xpwntool $1 /dev/null | grep -v match | tr -cd [:alnum:] | sed 's/0x//g'`
	if [ "$NONCE" ]
	then
		KEYIV=`./aes dec GID $NONCE`
		IV=`echo $KEYIV | sed 's/\([a-z0-9]\{32\}\).*/\\1/'`
		KEY=`echo $KEYIV | sed 's/[a-z0-9]\{32\}//'`
		echo "	<key>$FILEPATH</key>"
		echo "	<dict>"
		echo "		<key>IV</key>"
		echo "		<string>$IV</string>"
		echo "		<key>Key</key>"
		echo "		<string>$KEY</string>"
		echo "	</dict>"
	fi
fi

