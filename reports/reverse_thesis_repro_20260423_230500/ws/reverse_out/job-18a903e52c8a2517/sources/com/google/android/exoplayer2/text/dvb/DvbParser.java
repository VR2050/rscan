package com.google.android.exoplayer2.text.dvb;

import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffXfermode;
import android.graphics.Region;
import android.util.SparseArray;
import com.google.android.exoplayer2.text.Cue;
import com.google.android.exoplayer2.util.Log;
import com.google.android.exoplayer2.util.ParsableBitArray;
import com.google.android.exoplayer2.util.Util;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/* JADX INFO: loaded from: classes2.dex */
final class DvbParser {
    private static final int DATA_TYPE_24_TABLE_DATA = 32;
    private static final int DATA_TYPE_28_TABLE_DATA = 33;
    private static final int DATA_TYPE_2BP_CODE_STRING = 16;
    private static final int DATA_TYPE_48_TABLE_DATA = 34;
    private static final int DATA_TYPE_4BP_CODE_STRING = 17;
    private static final int DATA_TYPE_8BP_CODE_STRING = 18;
    private static final int DATA_TYPE_END_LINE = 240;
    private static final int OBJECT_CODING_PIXELS = 0;
    private static final int OBJECT_CODING_STRING = 1;
    private static final int PAGE_STATE_NORMAL = 0;
    private static final int REGION_DEPTH_4_BIT = 2;
    private static final int REGION_DEPTH_8_BIT = 3;
    private static final int SEGMENT_TYPE_CLUT_DEFINITION = 18;
    private static final int SEGMENT_TYPE_DISPLAY_DEFINITION = 20;
    private static final int SEGMENT_TYPE_OBJECT_DATA = 19;
    private static final int SEGMENT_TYPE_PAGE_COMPOSITION = 16;
    private static final int SEGMENT_TYPE_REGION_COMPOSITION = 17;
    private static final String TAG = "DvbParser";
    private static final byte[] defaultMap2To4 = {0, 7, 8, 15};
    private static final byte[] defaultMap2To8 = {0, 119, -120, -1};
    private static final byte[] defaultMap4To8 = {0, 17, 34, 51, 68, 85, 102, 119, -120, -103, -86, -69, -52, -35, -18, -1};
    private Bitmap bitmap;
    private final Canvas canvas;
    private final ClutDefinition defaultClutDefinition;
    private final DisplayDefinition defaultDisplayDefinition;
    private final Paint defaultPaint;
    private final Paint fillRegionPaint;
    private final SubtitleService subtitleService;

    public DvbParser(int subtitlePageId, int ancillaryPageId) {
        Paint paint = new Paint();
        this.defaultPaint = paint;
        paint.setStyle(Paint.Style.FILL_AND_STROKE);
        this.defaultPaint.setXfermode(new PorterDuffXfermode(PorterDuff.Mode.SRC));
        this.defaultPaint.setPathEffect(null);
        Paint paint2 = new Paint();
        this.fillRegionPaint = paint2;
        paint2.setStyle(Paint.Style.FILL);
        this.fillRegionPaint.setXfermode(new PorterDuffXfermode(PorterDuff.Mode.DST_OVER));
        this.fillRegionPaint.setPathEffect(null);
        this.canvas = new Canvas();
        this.defaultDisplayDefinition = new DisplayDefinition(719, 575, 0, 719, 0, 575);
        this.defaultClutDefinition = new ClutDefinition(0, generateDefault2BitClutEntries(), generateDefault4BitClutEntries(), generateDefault8BitClutEntries());
        this.subtitleService = new SubtitleService(subtitlePageId, ancillaryPageId);
    }

    public void reset() {
        this.subtitleService.reset();
    }

    public List<Cue> decode(byte[] data, int limit) {
        int color;
        PageRegion pageRegion;
        ParsableBitArray dataBitArray = new ParsableBitArray(data, limit);
        while (dataBitArray.bitsLeft() >= 48 && dataBitArray.readBits(8) == 15) {
            parseSubtitlingSegment(dataBitArray, this.subtitleService);
        }
        if (this.subtitleService.pageComposition == null) {
            return Collections.emptyList();
        }
        DisplayDefinition displayDefinition = this.subtitleService.displayDefinition != null ? this.subtitleService.displayDefinition : this.defaultDisplayDefinition;
        if (this.bitmap == null || displayDefinition.width + 1 != this.bitmap.getWidth() || displayDefinition.height + 1 != this.bitmap.getHeight()) {
            Bitmap bitmapCreateBitmap = Bitmap.createBitmap(displayDefinition.width + 1, displayDefinition.height + 1, Bitmap.Config.ARGB_8888);
            this.bitmap = bitmapCreateBitmap;
            this.canvas.setBitmap(bitmapCreateBitmap);
        }
        List<Cue> cues = new ArrayList<>();
        SparseArray<PageRegion> pageRegions = this.subtitleService.pageComposition.regions;
        int i = 0;
        while (i < pageRegions.size()) {
            PageRegion pageRegion2 = pageRegions.valueAt(i);
            int regionId = pageRegions.keyAt(i);
            RegionComposition regionComposition = this.subtitleService.regions.get(regionId);
            int baseHorizontalAddress = pageRegion2.horizontalAddress + displayDefinition.horizontalPositionMinimum;
            int baseVerticalAddress = pageRegion2.verticalAddress + displayDefinition.verticalPositionMinimum;
            int clipRight = Math.min(regionComposition.width + baseHorizontalAddress, displayDefinition.horizontalPositionMaximum);
            int clipBottom = Math.min(regionComposition.height + baseVerticalAddress, displayDefinition.verticalPositionMaximum);
            ParsableBitArray dataBitArray2 = dataBitArray;
            SparseArray<PageRegion> pageRegions2 = pageRegions;
            this.canvas.clipRect(baseHorizontalAddress, baseVerticalAddress, clipRight, clipBottom, Region.Op.REPLACE);
            ClutDefinition clutDefinition = this.subtitleService.cluts.get(regionComposition.clutId);
            if (clutDefinition == null && (clutDefinition = this.subtitleService.ancillaryCluts.get(regionComposition.clutId)) == null) {
                clutDefinition = this.defaultClutDefinition;
            }
            SparseArray<RegionObject> regionObjects = regionComposition.regionObjects;
            int j = 0;
            while (j < regionObjects.size()) {
                int objectId = regionObjects.keyAt(j);
                RegionObject regionObject = regionObjects.valueAt(j);
                SparseArray<RegionObject> regionObjects2 = regionObjects;
                ObjectData objectData = this.subtitleService.objects.get(objectId);
                if (objectData == null) {
                    objectData = this.subtitleService.ancillaryObjects.get(objectId);
                }
                if (objectData != null) {
                    Paint paint = objectData.nonModifyingColorFlag ? null : this.defaultPaint;
                    pageRegion = pageRegion2;
                    paintPixelDataSubBlocks(objectData, clutDefinition, regionComposition.depth, baseHorizontalAddress + regionObject.horizontalPosition, baseVerticalAddress + regionObject.verticalPosition, paint, this.canvas);
                } else {
                    pageRegion = pageRegion2;
                }
                j++;
                regionObjects = regionObjects2;
                pageRegion2 = pageRegion;
            }
            if (regionComposition.fillFlag) {
                if (regionComposition.depth == 3) {
                    color = clutDefinition.clutEntries8Bit[regionComposition.pixelCode8Bit];
                } else {
                    int color2 = regionComposition.depth;
                    if (color2 == 2) {
                        color = clutDefinition.clutEntries4Bit[regionComposition.pixelCode4Bit];
                    } else {
                        color = clutDefinition.clutEntries2Bit[regionComposition.pixelCode2Bit];
                    }
                }
                this.fillRegionPaint.setColor(color);
                this.canvas.drawRect(baseHorizontalAddress, baseVerticalAddress, regionComposition.width + baseHorizontalAddress, regionComposition.height + baseVerticalAddress, this.fillRegionPaint);
            }
            Bitmap cueBitmap = Bitmap.createBitmap(this.bitmap, baseHorizontalAddress, baseVerticalAddress, regionComposition.width, regionComposition.height);
            cues.add(new Cue(cueBitmap, baseHorizontalAddress / displayDefinition.width, 0, baseVerticalAddress / displayDefinition.height, 0, regionComposition.width / displayDefinition.width, regionComposition.height / displayDefinition.height));
            this.canvas.drawColor(0, PorterDuff.Mode.CLEAR);
            i++;
            dataBitArray = dataBitArray2;
            pageRegions = pageRegions2;
        }
        return cues;
    }

    private static void parseSubtitlingSegment(ParsableBitArray data, SubtitleService service) {
        int segmentType = data.readBits(8);
        int pageId = data.readBits(16);
        int dataFieldLength = data.readBits(16);
        int dataFieldLimit = data.getBytePosition() + dataFieldLength;
        if (dataFieldLength * 8 > data.bitsLeft()) {
            Log.w(TAG, "Data field length exceeds limit");
            data.skipBits(data.bitsLeft());
            return;
        }
        switch (segmentType) {
            case 16:
                if (pageId == service.subtitlePageId) {
                    PageComposition current = service.pageComposition;
                    PageComposition pageComposition = parsePageComposition(data, dataFieldLength);
                    if (pageComposition.state != 0) {
                        service.pageComposition = pageComposition;
                        service.regions.clear();
                        service.cluts.clear();
                        service.objects.clear();
                    } else if (current != null && current.version != pageComposition.version) {
                        service.pageComposition = pageComposition;
                    }
                }
                break;
            case 17:
                PageComposition pageComposition2 = service.pageComposition;
                if (pageId == service.subtitlePageId && pageComposition2 != null) {
                    RegionComposition regionComposition = parseRegionComposition(data, dataFieldLength);
                    if (pageComposition2.state == 0) {
                        regionComposition.mergeFrom(service.regions.get(regionComposition.id));
                    }
                    service.regions.put(regionComposition.id, regionComposition);
                }
                break;
            case 18:
                if (pageId == service.subtitlePageId) {
                    ClutDefinition clutDefinition = parseClutDefinition(data, dataFieldLength);
                    service.cluts.put(clutDefinition.id, clutDefinition);
                } else if (pageId == service.ancillaryPageId) {
                    ClutDefinition clutDefinition2 = parseClutDefinition(data, dataFieldLength);
                    service.ancillaryCluts.put(clutDefinition2.id, clutDefinition2);
                }
                break;
            case 19:
                if (pageId == service.subtitlePageId) {
                    ObjectData objectData = parseObjectData(data);
                    service.objects.put(objectData.id, objectData);
                } else if (pageId == service.ancillaryPageId) {
                    ObjectData objectData2 = parseObjectData(data);
                    service.ancillaryObjects.put(objectData2.id, objectData2);
                }
                break;
            case 20:
                if (pageId == service.subtitlePageId) {
                    service.displayDefinition = parseDisplayDefinition(data);
                }
                break;
        }
        data.skipBytes(dataFieldLimit - data.getBytePosition());
    }

    private static DisplayDefinition parseDisplayDefinition(ParsableBitArray data) {
        int verticalPositionMaximum;
        int horizontalPositionMinimum;
        int horizontalPositionMaximum;
        int verticalPositionMinimum;
        data.skipBits(4);
        boolean displayWindowFlag = data.readBit();
        data.skipBits(3);
        int width = data.readBits(16);
        int height = data.readBits(16);
        if (displayWindowFlag) {
            int horizontalPositionMinimum2 = data.readBits(16);
            int horizontalPositionMaximum2 = data.readBits(16);
            int verticalPositionMinimum2 = data.readBits(16);
            verticalPositionMaximum = data.readBits(16);
            horizontalPositionMinimum = horizontalPositionMinimum2;
            horizontalPositionMaximum = horizontalPositionMaximum2;
            verticalPositionMinimum = verticalPositionMinimum2;
        } else {
            verticalPositionMaximum = height;
            horizontalPositionMinimum = 0;
            horizontalPositionMaximum = width;
            verticalPositionMinimum = 0;
        }
        return new DisplayDefinition(width, height, horizontalPositionMinimum, horizontalPositionMaximum, verticalPositionMinimum, verticalPositionMaximum);
    }

    private static PageComposition parsePageComposition(ParsableBitArray data, int length) {
        int timeoutSecs = data.readBits(8);
        int version = data.readBits(4);
        int state = data.readBits(2);
        data.skipBits(2);
        int remainingLength = length - 2;
        SparseArray<PageRegion> regions = new SparseArray<>();
        while (remainingLength > 0) {
            int regionId = data.readBits(8);
            data.skipBits(8);
            int regionHorizontalAddress = data.readBits(16);
            int regionVerticalAddress = data.readBits(16);
            remainingLength -= 6;
            regions.put(regionId, new PageRegion(regionHorizontalAddress, regionVerticalAddress));
        }
        return new PageComposition(timeoutSecs, version, state, regions);
    }

    private static RegionComposition parseRegionComposition(ParsableBitArray data, int length) {
        int i = 8;
        int id = data.readBits(8);
        data.skipBits(4);
        boolean fillFlag = data.readBit();
        data.skipBits(3);
        int width = data.readBits(16);
        int height = data.readBits(16);
        int levelOfCompatibility = data.readBits(3);
        int depth = data.readBits(3);
        data.skipBits(2);
        int clutId = data.readBits(8);
        int pixelCode8Bit = data.readBits(8);
        int pixelCode4Bit = data.readBits(4);
        int pixelCode2Bit = data.readBits(2);
        data.skipBits(2);
        SparseArray<RegionObject> regionObjects = new SparseArray<>();
        int foregroundPixelCode = length - 10;
        while (foregroundPixelCode > 0) {
            int objectId = data.readBits(16);
            int objectType = data.readBits(2);
            int objectProvider = data.readBits(2);
            int objectHorizontalPosition = data.readBits(12);
            data.skipBits(4);
            int objectVerticalPosition = data.readBits(12);
            int remainingLength = foregroundPixelCode - 6;
            int foregroundPixelCode2 = 0;
            int backgroundPixelCode = 0;
            if (objectType == 1 || objectType == 2) {
                foregroundPixelCode2 = data.readBits(i);
                backgroundPixelCode = data.readBits(i);
                remainingLength -= 2;
            }
            regionObjects.put(objectId, new RegionObject(objectType, objectProvider, objectHorizontalPosition, objectVerticalPosition, foregroundPixelCode2, backgroundPixelCode));
            foregroundPixelCode = remainingLength;
            i = 8;
        }
        return new RegionComposition(id, fillFlag, width, height, levelOfCompatibility, depth, clutId, pixelCode8Bit, pixelCode4Bit, pixelCode2Bit, regionObjects);
    }

    private static ClutDefinition parseClutDefinition(ParsableBitArray data, int length) {
        int[] clutEntries;
        int remainingLength;
        int cb;
        int cb2;
        int t;
        int y;
        ParsableBitArray parsableBitArray = data;
        int i = 8;
        int clutId = parsableBitArray.readBits(8);
        parsableBitArray.skipBits(8);
        int remainingLength2 = length - 2;
        int[] clutEntries2Bit = generateDefault2BitClutEntries();
        int[] clutEntries4Bit = generateDefault4BitClutEntries();
        int[] clutEntries8Bit = generateDefault8BitClutEntries();
        while (remainingLength2 > 0) {
            int entryId = parsableBitArray.readBits(i);
            int entryFlags = parsableBitArray.readBits(i);
            int remainingLength3 = remainingLength2 - 2;
            if ((entryFlags & 128) != 0) {
                clutEntries = clutEntries2Bit;
            } else if ((entryFlags & 64) != 0) {
                clutEntries = clutEntries4Bit;
            } else {
                clutEntries = clutEntries8Bit;
            }
            if ((entryFlags & 1) != 0) {
                t = parsableBitArray.readBits(i);
                y = parsableBitArray.readBits(i);
                cb = parsableBitArray.readBits(i);
                cb2 = parsableBitArray.readBits(i);
                remainingLength = remainingLength3 - 4;
            } else {
                int y2 = parsableBitArray.readBits(6) << 2;
                int cr = parsableBitArray.readBits(4) << 4;
                int cb3 = parsableBitArray.readBits(4) << 4;
                int t2 = parsableBitArray.readBits(2) << 6;
                remainingLength = remainingLength3 - 2;
                cb = cb3;
                cb2 = t2;
                t = y2;
                y = cr;
            }
            if (t == 0) {
                y = 0;
                cb = 0;
                cb2 = 255;
            }
            int a = (byte) (255 - (cb2 & 255));
            int clutId2 = clutId;
            int r = (int) (((double) t) + (((double) (y - 128)) * 1.402d));
            int g = (int) ((((double) t) - (((double) (cb - 128)) * 0.34414d)) - (((double) (y - 128)) * 0.71414d));
            int b = (int) (((double) t) + (((double) (cb - 128)) * 1.772d));
            clutEntries[entryId] = getColor(a, Util.constrainValue(r, 0, 255), Util.constrainValue(g, 0, 255), Util.constrainValue(b, 0, 255));
            parsableBitArray = data;
            clutEntries4Bit = clutEntries4Bit;
            clutId = clutId2;
            clutEntries8Bit = clutEntries8Bit;
            clutEntries2Bit = clutEntries2Bit;
            remainingLength2 = remainingLength;
            i = 8;
        }
        return new ClutDefinition(clutId, clutEntries2Bit, clutEntries4Bit, clutEntries8Bit);
    }

    private static ObjectData parseObjectData(ParsableBitArray data) {
        int objectId = data.readBits(16);
        data.skipBits(4);
        int objectCodingMethod = data.readBits(2);
        boolean nonModifyingColorFlag = data.readBit();
        data.skipBits(1);
        byte[] topFieldData = null;
        byte[] bottomFieldData = null;
        if (objectCodingMethod == 1) {
            int numberOfCodes = data.readBits(8);
            data.skipBits(numberOfCodes * 16);
        } else if (objectCodingMethod == 0) {
            int topFieldDataLength = data.readBits(16);
            int bottomFieldDataLength = data.readBits(16);
            if (topFieldDataLength > 0) {
                topFieldData = new byte[topFieldDataLength];
                data.readBytes(topFieldData, 0, topFieldDataLength);
            }
            if (bottomFieldDataLength > 0) {
                bottomFieldData = new byte[bottomFieldDataLength];
                data.readBytes(bottomFieldData, 0, bottomFieldDataLength);
            } else {
                bottomFieldData = topFieldData;
            }
        }
        return new ObjectData(objectId, nonModifyingColorFlag, topFieldData, bottomFieldData);
    }

    private static int[] generateDefault2BitClutEntries() {
        int[] entries = {0, -1, -16777216, -8421505};
        return entries;
    }

    private static int[] generateDefault4BitClutEntries() {
        int[] entries = new int[16];
        entries[0] = 0;
        for (int i = 1; i < entries.length; i++) {
            if (i < 8) {
                entries[i] = getColor(255, (i & 1) != 0 ? 255 : 0, (i & 2) != 0 ? 255 : 0, (i & 4) != 0 ? 255 : 0);
            } else {
                entries[i] = getColor(255, (i & 1) != 0 ? 127 : 0, (i & 2) != 0 ? 127 : 0, (i & 4) == 0 ? 0 : 127);
            }
        }
        return entries;
    }

    private static int[] generateDefault8BitClutEntries() {
        int[] entries = new int[256];
        entries[0] = 0;
        for (int i = 0; i < entries.length; i++) {
            if (i < 8) {
                entries[i] = getColor(63, (i & 1) != 0 ? 255 : 0, (i & 2) != 0 ? 255 : 0, (i & 4) == 0 ? 0 : 255);
            } else {
                int i2 = i & 136;
                if (i2 == 0) {
                    entries[i] = getColor(255, ((i & 1) != 0 ? 85 : 0) + ((i & 16) != 0 ? 170 : 0), ((i & 2) != 0 ? 85 : 0) + ((i & 32) != 0 ? 170 : 0), ((i & 4) == 0 ? 0 : 85) + ((i & 64) == 0 ? 0 : 170));
                } else if (i2 == 8) {
                    entries[i] = getColor(127, ((i & 1) != 0 ? 85 : 0) + ((i & 16) != 0 ? 170 : 0), ((i & 2) != 0 ? 85 : 0) + ((i & 32) != 0 ? 170 : 0), ((i & 4) == 0 ? 0 : 85) + ((i & 64) == 0 ? 0 : 170));
                } else if (i2 == 128) {
                    entries[i] = getColor(255, ((i & 1) != 0 ? 43 : 0) + 127 + ((i & 16) != 0 ? 85 : 0), ((i & 2) != 0 ? 43 : 0) + 127 + ((i & 32) != 0 ? 85 : 0), ((i & 4) == 0 ? 0 : 43) + 127 + ((i & 64) == 0 ? 0 : 85));
                } else if (i2 == 136) {
                    entries[i] = getColor(255, ((i & 1) != 0 ? 43 : 0) + ((i & 16) != 0 ? 85 : 0), ((i & 2) != 0 ? 43 : 0) + ((i & 32) != 0 ? 85 : 0), ((i & 4) == 0 ? 0 : 43) + ((i & 64) == 0 ? 0 : 85));
                }
            }
        }
        return entries;
    }

    private static int getColor(int a, int r, int g, int b) {
        return (a << 24) | (r << 16) | (g << 8) | b;
    }

    private static void paintPixelDataSubBlocks(ObjectData objectData, ClutDefinition clutDefinition, int regionDepth, int horizontalAddress, int verticalAddress, Paint paint, Canvas canvas) {
        int[] clutEntries;
        if (regionDepth == 3) {
            clutEntries = clutDefinition.clutEntries8Bit;
        } else if (regionDepth == 2) {
            clutEntries = clutDefinition.clutEntries4Bit;
        } else {
            clutEntries = clutDefinition.clutEntries2Bit;
        }
        int[] iArr = clutEntries;
        paintPixelDataSubBlock(objectData.topFieldData, iArr, regionDepth, horizontalAddress, verticalAddress, paint, canvas);
        paintPixelDataSubBlock(objectData.bottomFieldData, iArr, regionDepth, horizontalAddress, verticalAddress + 1, paint, canvas);
    }

    /* JADX WARN: Incorrect condition in loop: B:4:0x0018 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private static void paintPixelDataSubBlock(byte[] r17, int[] r18, int r19, int r20, int r21, android.graphics.Paint r22, android.graphics.Canvas r23) {
        /*
            r0 = r19
            com.google.android.exoplayer2.util.ParsableBitArray r1 = new com.google.android.exoplayer2.util.ParsableBitArray
            r2 = r17
            r1.<init>(r2)
            r3 = r20
            r4 = r21
            r5 = 0
            r6 = 0
            r10 = 0
            r11 = r3
            r12 = r4
            r13 = r5
            r14 = r6
        L14:
            int r3 = r1.bitsLeft()
            if (r3 == 0) goto Lad
            r3 = 8
            int r15 = r1.readBits(r3)
            r4 = 240(0xf0, float:3.36E-43)
            if (r15 == r4) goto La6
            r4 = 3
            switch(r15) {
                case 16: goto L78;
                case 17: goto L56;
                case 18: goto L45;
                default: goto L28;
            }
        L28:
            r4 = 4
            switch(r15) {
                case 32: goto L3e;
                case 33: goto L37;
                case 34: goto L2e;
                default: goto L2c;
            }
        L2c:
            goto Lab
        L2e:
            r4 = 16
            byte[] r3 = buildClutMapTable(r4, r3, r1)
            r14 = r3
            goto Lab
        L37:
            byte[] r3 = buildClutMapTable(r4, r3, r1)
            r14 = r3
            goto Lab
        L3e:
            byte[] r3 = buildClutMapTable(r4, r4, r1)
            r13 = r3
            goto Lab
        L45:
            r5 = 0
            r3 = r1
            r4 = r18
            r6 = r11
            r7 = r12
            r8 = r22
            r9 = r23
            int r3 = paint8BitPixelCodeString(r3, r4, r5, r6, r7, r8, r9)
            r11 = r3
            goto Lab
        L56:
            if (r0 != r4) goto L61
            if (r10 != 0) goto L5d
            byte[] r3 = com.google.android.exoplayer2.text.dvb.DvbParser.defaultMap4To8
            goto L5e
        L5d:
            r3 = r10
        L5e:
            r16 = r3
            goto L64
        L61:
            r3 = 0
            r16 = r3
        L64:
            r3 = r1
            r4 = r18
            r5 = r16
            r6 = r11
            r7 = r12
            r8 = r22
            r9 = r23
            int r3 = paint4BitPixelCodeString(r3, r4, r5, r6, r7, r8, r9)
            r1.byteAlign()
            r11 = r3
            goto Lab
        L78:
            if (r0 != r4) goto L83
            if (r14 != 0) goto L7f
            byte[] r3 = com.google.android.exoplayer2.text.dvb.DvbParser.defaultMap2To8
            goto L80
        L7f:
            r3 = r14
        L80:
            r16 = r3
            goto L92
        L83:
            r3 = 2
            if (r0 != r3) goto L8f
            if (r13 != 0) goto L8b
            byte[] r3 = com.google.android.exoplayer2.text.dvb.DvbParser.defaultMap2To4
            goto L8c
        L8b:
            r3 = r13
        L8c:
            r16 = r3
            goto L92
        L8f:
            r3 = 0
            r16 = r3
        L92:
            r3 = r1
            r4 = r18
            r5 = r16
            r6 = r11
            r7 = r12
            r8 = r22
            r9 = r23
            int r3 = paint2BitPixelCodeString(r3, r4, r5, r6, r7, r8, r9)
            r1.byteAlign()
            r11 = r3
            goto Lab
        La6:
            r3 = r20
            int r12 = r12 + 2
            r11 = r3
        Lab:
            goto L14
        Lad:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.exoplayer2.text.dvb.DvbParser.paintPixelDataSubBlock(byte[], int[], int, int, int, android.graphics.Paint, android.graphics.Canvas):void");
    }

    private static int paint2BitPixelCodeString(ParsableBitArray data, int[] clutEntries, byte[] bArr, int column, int line, Paint paint, Canvas canvas) {
        boolean endOfPixelCodeString;
        int runLength;
        int clutIndex;
        boolean endOfPixelCodeString2 = false;
        int column2 = column;
        while (true) {
            int peek = data.readBits(2);
            if (peek != 0) {
                endOfPixelCodeString = endOfPixelCodeString2;
                runLength = 1;
                clutIndex = peek;
            } else if (data.readBit()) {
                int runLength2 = data.readBits(3) + 3;
                int clutIndex2 = data.readBits(2);
                endOfPixelCodeString = endOfPixelCodeString2;
                runLength = runLength2;
                clutIndex = clutIndex2;
            } else if (data.readBit()) {
                endOfPixelCodeString = endOfPixelCodeString2;
                runLength = 1;
                clutIndex = 0;
            } else {
                int bits = data.readBits(2);
                if (bits == 0) {
                    endOfPixelCodeString = true;
                    runLength = 0;
                    clutIndex = 0;
                } else if (bits != 1) {
                    if (bits == 2) {
                        int runLength3 = data.readBits(4) + 12;
                        int clutIndex3 = data.readBits(2);
                        endOfPixelCodeString = endOfPixelCodeString2;
                        runLength = runLength3;
                        clutIndex = clutIndex3;
                    } else if (bits != 3) {
                        endOfPixelCodeString = endOfPixelCodeString2;
                        runLength = 0;
                        clutIndex = 0;
                    } else {
                        int runLength4 = data.readBits(8) + 29;
                        int clutIndex4 = data.readBits(2);
                        endOfPixelCodeString = endOfPixelCodeString2;
                        runLength = runLength4;
                        clutIndex = clutIndex4;
                    }
                } else {
                    endOfPixelCodeString = endOfPixelCodeString2;
                    runLength = 2;
                    clutIndex = 0;
                }
            }
            if (runLength != 0 && paint != null) {
                paint.setColor(clutEntries[bArr != null ? bArr[clutIndex] : clutIndex]);
                canvas.drawRect(column2, line, column2 + runLength, line + 1, paint);
            }
            column2 += runLength;
            if (!endOfPixelCodeString) {
                endOfPixelCodeString2 = endOfPixelCodeString;
            } else {
                return column2;
            }
        }
    }

    private static int paint4BitPixelCodeString(ParsableBitArray data, int[] clutEntries, byte[] bArr, int column, int line, Paint paint, Canvas canvas) {
        boolean endOfPixelCodeString;
        int runLength;
        int clutIndex;
        boolean endOfPixelCodeString2 = false;
        int column2 = column;
        while (true) {
            int peek = data.readBits(4);
            if (peek != 0) {
                endOfPixelCodeString = endOfPixelCodeString2;
                runLength = 1;
                clutIndex = peek;
            } else if (!data.readBit()) {
                int peek2 = data.readBits(3);
                if (peek2 != 0) {
                    int runLength2 = peek2 + 2;
                    endOfPixelCodeString = endOfPixelCodeString2;
                    runLength = runLength2;
                    clutIndex = 0;
                } else {
                    endOfPixelCodeString = true;
                    runLength = 0;
                    clutIndex = 0;
                }
            } else if (!data.readBit()) {
                int runLength3 = data.readBits(2) + 4;
                int clutIndex2 = data.readBits(4);
                endOfPixelCodeString = endOfPixelCodeString2;
                runLength = runLength3;
                clutIndex = clutIndex2;
            } else {
                int bits = data.readBits(2);
                if (bits == 0) {
                    endOfPixelCodeString = endOfPixelCodeString2;
                    runLength = 1;
                    clutIndex = 0;
                } else if (bits == 1) {
                    endOfPixelCodeString = endOfPixelCodeString2;
                    runLength = 2;
                    clutIndex = 0;
                } else if (bits == 2) {
                    int runLength4 = data.readBits(4) + 9;
                    int clutIndex3 = data.readBits(4);
                    endOfPixelCodeString = endOfPixelCodeString2;
                    runLength = runLength4;
                    clutIndex = clutIndex3;
                } else if (bits != 3) {
                    endOfPixelCodeString = endOfPixelCodeString2;
                    runLength = 0;
                    clutIndex = 0;
                } else {
                    int runLength5 = data.readBits(8) + 25;
                    int clutIndex4 = data.readBits(4);
                    endOfPixelCodeString = endOfPixelCodeString2;
                    runLength = runLength5;
                    clutIndex = clutIndex4;
                }
            }
            if (runLength != 0 && paint != null) {
                paint.setColor(clutEntries[bArr != null ? bArr[clutIndex] : clutIndex]);
                canvas.drawRect(column2, line, column2 + runLength, line + 1, paint);
            }
            column2 += runLength;
            if (!endOfPixelCodeString) {
                endOfPixelCodeString2 = endOfPixelCodeString;
            } else {
                return column2;
            }
        }
    }

    private static int paint8BitPixelCodeString(ParsableBitArray data, int[] clutEntries, byte[] bArr, int column, int line, Paint paint, Canvas canvas) {
        boolean endOfPixelCodeString;
        int runLength;
        int clutIndex;
        boolean endOfPixelCodeString2 = false;
        int column2 = column;
        while (true) {
            int peek = data.readBits(8);
            if (peek != 0) {
                endOfPixelCodeString = endOfPixelCodeString2;
                runLength = 1;
                clutIndex = peek;
            } else if (!data.readBit()) {
                int peek2 = data.readBits(7);
                if (peek2 != 0) {
                    endOfPixelCodeString = endOfPixelCodeString2;
                    runLength = peek2;
                    clutIndex = 0;
                } else {
                    endOfPixelCodeString = true;
                    runLength = 0;
                    clutIndex = 0;
                }
            } else {
                int runLength2 = data.readBits(7);
                int clutIndex2 = data.readBits(8);
                endOfPixelCodeString = endOfPixelCodeString2;
                runLength = runLength2;
                clutIndex = clutIndex2;
            }
            if (runLength != 0 && paint != null) {
                paint.setColor(clutEntries[bArr != null ? bArr[clutIndex] : clutIndex]);
                canvas.drawRect(column2, line, column2 + runLength, line + 1, paint);
            }
            column2 += runLength;
            if (!endOfPixelCodeString) {
                endOfPixelCodeString2 = endOfPixelCodeString;
            } else {
                return column2;
            }
        }
    }

    private static byte[] buildClutMapTable(int length, int bitsPerEntry, ParsableBitArray data) {
        byte[] clutMapTable = new byte[length];
        for (int i = 0; i < length; i++) {
            clutMapTable[i] = (byte) data.readBits(bitsPerEntry);
        }
        return clutMapTable;
    }

    private static final class SubtitleService {
        public final int ancillaryPageId;
        public DisplayDefinition displayDefinition;
        public PageComposition pageComposition;
        public final int subtitlePageId;
        public final SparseArray<RegionComposition> regions = new SparseArray<>();
        public final SparseArray<ClutDefinition> cluts = new SparseArray<>();
        public final SparseArray<ObjectData> objects = new SparseArray<>();
        public final SparseArray<ClutDefinition> ancillaryCluts = new SparseArray<>();
        public final SparseArray<ObjectData> ancillaryObjects = new SparseArray<>();

        public SubtitleService(int subtitlePageId, int ancillaryPageId) {
            this.subtitlePageId = subtitlePageId;
            this.ancillaryPageId = ancillaryPageId;
        }

        public void reset() {
            this.regions.clear();
            this.cluts.clear();
            this.objects.clear();
            this.ancillaryCluts.clear();
            this.ancillaryObjects.clear();
            this.displayDefinition = null;
            this.pageComposition = null;
        }
    }

    private static final class DisplayDefinition {
        public final int height;
        public final int horizontalPositionMaximum;
        public final int horizontalPositionMinimum;
        public final int verticalPositionMaximum;
        public final int verticalPositionMinimum;
        public final int width;

        public DisplayDefinition(int width, int height, int horizontalPositionMinimum, int horizontalPositionMaximum, int verticalPositionMinimum, int verticalPositionMaximum) {
            this.width = width;
            this.height = height;
            this.horizontalPositionMinimum = horizontalPositionMinimum;
            this.horizontalPositionMaximum = horizontalPositionMaximum;
            this.verticalPositionMinimum = verticalPositionMinimum;
            this.verticalPositionMaximum = verticalPositionMaximum;
        }
    }

    private static final class PageComposition {
        public final SparseArray<PageRegion> regions;
        public final int state;
        public final int timeOutSecs;
        public final int version;

        public PageComposition(int timeoutSecs, int version, int state, SparseArray<PageRegion> regions) {
            this.timeOutSecs = timeoutSecs;
            this.version = version;
            this.state = state;
            this.regions = regions;
        }
    }

    private static final class PageRegion {
        public final int horizontalAddress;
        public final int verticalAddress;

        public PageRegion(int horizontalAddress, int verticalAddress) {
            this.horizontalAddress = horizontalAddress;
            this.verticalAddress = verticalAddress;
        }
    }

    private static final class RegionComposition {
        public final int clutId;
        public final int depth;
        public final boolean fillFlag;
        public final int height;
        public final int id;
        public final int levelOfCompatibility;
        public final int pixelCode2Bit;
        public final int pixelCode4Bit;
        public final int pixelCode8Bit;
        public final SparseArray<RegionObject> regionObjects;
        public final int width;

        public RegionComposition(int id, boolean fillFlag, int width, int height, int levelOfCompatibility, int depth, int clutId, int pixelCode8Bit, int pixelCode4Bit, int pixelCode2Bit, SparseArray<RegionObject> regionObjects) {
            this.id = id;
            this.fillFlag = fillFlag;
            this.width = width;
            this.height = height;
            this.levelOfCompatibility = levelOfCompatibility;
            this.depth = depth;
            this.clutId = clutId;
            this.pixelCode8Bit = pixelCode8Bit;
            this.pixelCode4Bit = pixelCode4Bit;
            this.pixelCode2Bit = pixelCode2Bit;
            this.regionObjects = regionObjects;
        }

        public void mergeFrom(RegionComposition otherRegionComposition) {
            if (otherRegionComposition == null) {
                return;
            }
            SparseArray<RegionObject> otherRegionObjects = otherRegionComposition.regionObjects;
            for (int i = 0; i < otherRegionObjects.size(); i++) {
                this.regionObjects.put(otherRegionObjects.keyAt(i), otherRegionObjects.valueAt(i));
            }
        }
    }

    private static final class RegionObject {
        public final int backgroundPixelCode;
        public final int foregroundPixelCode;
        public final int horizontalPosition;
        public final int provider;
        public final int type;
        public final int verticalPosition;

        public RegionObject(int type, int provider, int horizontalPosition, int verticalPosition, int foregroundPixelCode, int backgroundPixelCode) {
            this.type = type;
            this.provider = provider;
            this.horizontalPosition = horizontalPosition;
            this.verticalPosition = verticalPosition;
            this.foregroundPixelCode = foregroundPixelCode;
            this.backgroundPixelCode = backgroundPixelCode;
        }
    }

    private static final class ClutDefinition {
        public final int[] clutEntries2Bit;
        public final int[] clutEntries4Bit;
        public final int[] clutEntries8Bit;
        public final int id;

        public ClutDefinition(int id, int[] clutEntries2Bit, int[] clutEntries4Bit, int[] clutEntries8bit) {
            this.id = id;
            this.clutEntries2Bit = clutEntries2Bit;
            this.clutEntries4Bit = clutEntries4Bit;
            this.clutEntries8Bit = clutEntries8bit;
        }
    }

    private static final class ObjectData {
        public final byte[] bottomFieldData;
        public final int id;
        public final boolean nonModifyingColorFlag;
        public final byte[] topFieldData;

        public ObjectData(int id, boolean nonModifyingColorFlag, byte[] topFieldData, byte[] bottomFieldData) {
            this.id = id;
            this.nonModifyingColorFlag = nonModifyingColorFlag;
            this.topFieldData = topFieldData;
            this.bottomFieldData = bottomFieldData;
        }
    }
}
