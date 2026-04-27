package com.googlecode.mp4parser.srt;

import com.googlecode.mp4parser.authoring.tracks.TextTrackImpl;
import com.king.zxing.util.LogUtils;
import com.snail.antifake.deviceid.ShellAdbUtils;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.LineNumberReader;

/* JADX INFO: loaded from: classes.dex */
public class SrtParser {
    public static TextTrackImpl parse(InputStream is) throws IOException {
        LineNumberReader r = new LineNumberReader(new InputStreamReader(is, "UTF-8"));
        TextTrackImpl track = new TextTrackImpl();
        while (r.readLine() != null) {
            String timeString = r.readLine();
            String lineString = "";
            while (true) {
                String s = r.readLine();
                if (s == null || s.trim().equals("")) {
                    break;
                }
                lineString = String.valueOf(lineString) + s + ShellAdbUtils.COMMAND_LINE_END;
            }
            long startTime = parse(timeString.split("-->")[0]);
            long endTime = parse(timeString.split("-->")[1]);
            track.getSubs().add(new TextTrackImpl.Line(startTime, endTime, lineString));
            r = r;
            track = track;
        }
        return track;
    }

    private static long parse(String in) {
        long hours = Long.parseLong(in.split(LogUtils.COLON)[0].trim());
        long minutes = Long.parseLong(in.split(LogUtils.COLON)[1].trim());
        long seconds = Long.parseLong(in.split(LogUtils.COLON)[2].split(",")[0].trim());
        long millies = Long.parseLong(in.split(LogUtils.COLON)[2].split(",")[1].trim());
        return (hours * 60 * 60 * 1000) + (60 * minutes * 1000) + (1000 * seconds) + millies;
    }
}
