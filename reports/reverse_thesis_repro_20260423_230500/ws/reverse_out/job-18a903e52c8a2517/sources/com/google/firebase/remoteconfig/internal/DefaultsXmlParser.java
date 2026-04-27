package com.google.firebase.remoteconfig.internal;

/* JADX INFO: compiled from: com.google.firebase:firebase-config@@19.1.0 */
/* JADX INFO: loaded from: classes.dex */
public class DefaultsXmlParser {
    private static final String XML_TAG_ENTRY = "entry";
    private static final String XML_TAG_KEY = "key";
    private static final String XML_TAG_VALUE = "value";

    /* JADX WARN: Removed duplicated region for block: B:30:0x005e  */
    /* JADX WARN: Removed duplicated region for block: B:38:0x0075  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x0083 A[Catch: IOException -> 0x008f, IOException | XmlPullParserException -> 0x0091, TryCatch #2 {IOException | XmlPullParserException -> 0x0091, blocks: (B:3:0x0007, B:5:0x000d, B:7:0x0013, B:12:0x0024, B:42:0x0088, B:15:0x002d, B:19:0x003d, B:20:0x0041, B:26:0x004f, B:39:0x0077, B:40:0x007d, B:41:0x0083, B:31:0x005f, B:34:0x006a), top: B:50:0x0007 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.util.Map<java.lang.String, java.lang.String> getDefaultsFromXml(android.content.Context r12, int r13) {
        /*
            java.lang.String r0 = "FirebaseRemoteConfig"
            java.util.HashMap r1 = new java.util.HashMap
            r1.<init>()
            android.content.res.Resources r2 = r12.getResources()     // Catch: java.io.IOException -> L8f org.xmlpull.v1.XmlPullParserException -> L91
            if (r2 != 0) goto L13
            java.lang.String r3 = "Could not find the resources of the current context while trying to set defaults from an XML."
            android.util.Log.e(r0, r3)     // Catch: java.io.IOException -> L8f org.xmlpull.v1.XmlPullParserException -> L91
            return r1
        L13:
            android.content.res.XmlResourceParser r3 = r2.getXml(r13)     // Catch: java.io.IOException -> L8f org.xmlpull.v1.XmlPullParserException -> L91
            r4 = 0
            r5 = 0
            r6 = 0
            int r7 = r3.getEventType()     // Catch: java.io.IOException -> L8f org.xmlpull.v1.XmlPullParserException -> L91
        L1e:
            r8 = 1
            if (r7 == r8) goto L8e
            r9 = 2
            if (r7 != r9) goto L2a
            java.lang.String r8 = r3.getName()     // Catch: java.io.IOException -> L8f org.xmlpull.v1.XmlPullParserException -> L91
            r4 = r8
            goto L88
        L2a:
            r9 = 3
            if (r7 != r9) goto L4a
            java.lang.String r8 = r3.getName()     // Catch: java.io.IOException -> L8f org.xmlpull.v1.XmlPullParserException -> L91
            java.lang.String r9 = "entry"
            boolean r8 = r8.equals(r9)     // Catch: java.io.IOException -> L8f org.xmlpull.v1.XmlPullParserException -> L91
            if (r8 == 0) goto L48
            if (r5 == 0) goto L41
            if (r6 == 0) goto L41
            r1.put(r5, r6)     // Catch: java.io.IOException -> L8f org.xmlpull.v1.XmlPullParserException -> L91
            goto L46
        L41:
            java.lang.String r8 = "An entry in the defaults XML has an invalid key and/or value tag."
            android.util.Log.w(r0, r8)     // Catch: java.io.IOException -> L8f org.xmlpull.v1.XmlPullParserException -> L91
        L46:
            r5 = 0
            r6 = 0
        L48:
            r4 = 0
            goto L88
        L4a:
            r9 = 4
            if (r7 != r9) goto L88
            if (r4 == 0) goto L88
            r9 = -1
            int r10 = r4.hashCode()     // Catch: java.io.IOException -> L8f org.xmlpull.v1.XmlPullParserException -> L91
            r11 = 106079(0x19e5f, float:1.48648E-40)
            if (r10 == r11) goto L6a
            r11 = 111972721(0x6ac9171, float:6.4912916E-35)
            if (r10 == r11) goto L5f
        L5e:
            goto L73
        L5f:
            java.lang.String r10 = "value"
            boolean r10 = r4.equals(r10)     // Catch: java.io.IOException -> L8f org.xmlpull.v1.XmlPullParserException -> L91
            if (r10 == 0) goto L5e
            r9 = 1
            goto L73
        L6a:
            java.lang.String r10 = "key"
            boolean r10 = r4.equals(r10)     // Catch: java.io.IOException -> L8f org.xmlpull.v1.XmlPullParserException -> L91
            if (r10 == 0) goto L5e
            r9 = 0
        L73:
            if (r9 == 0) goto L83
            if (r9 == r8) goto L7d
            java.lang.String r8 = "Encountered an unexpected tag while parsing the defaults XML."
            android.util.Log.w(r0, r8)     // Catch: java.io.IOException -> L8f org.xmlpull.v1.XmlPullParserException -> L91
            goto L88
        L7d:
            java.lang.String r8 = r3.getText()     // Catch: java.io.IOException -> L8f org.xmlpull.v1.XmlPullParserException -> L91
            r6 = r8
            goto L88
        L83:
            java.lang.String r8 = r3.getText()     // Catch: java.io.IOException -> L8f org.xmlpull.v1.XmlPullParserException -> L91
            r5 = r8
        L88:
            int r8 = r3.next()     // Catch: java.io.IOException -> L8f org.xmlpull.v1.XmlPullParserException -> L91
            r7 = r8
            goto L1e
        L8e:
            goto L97
        L8f:
            r2 = move-exception
            goto L92
        L91:
            r2 = move-exception
        L92:
            java.lang.String r3 = "Encountered an error while parsing the defaults XML file."
            android.util.Log.e(r0, r3, r2)
        L97:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.remoteconfig.internal.DefaultsXmlParser.getDefaultsFromXml(android.content.Context, int):java.util.Map");
    }
}
