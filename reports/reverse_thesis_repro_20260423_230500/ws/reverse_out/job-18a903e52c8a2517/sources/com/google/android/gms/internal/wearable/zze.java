package com.google.android.gms.internal.wearable;

import com.google.android.exoplayer2.extractor.ts.TsExtractor;
import com.google.android.gms.wearable.Asset;
import com.google.android.gms.wearable.DataMap;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeSet;

/* JADX INFO: loaded from: classes.dex */
public final class zze {
    public static zzf zza(DataMap dataMap) {
        zzg zzgVar = new zzg();
        ArrayList arrayList = new ArrayList();
        TreeSet<String> treeSet = new TreeSet(dataMap.keySet());
        zzh[] zzhVarArr = new zzh[treeSet.size()];
        int i = 0;
        for (String str : treeSet) {
            Object obj = dataMap.get(str);
            zzhVarArr[i] = new zzh();
            zzhVarArr[i].name = str;
            zzhVarArr[i].zzga = zza(arrayList, obj);
            i++;
        }
        zzgVar.zzfy = zzhVarArr;
        return new zzf(zzgVar, arrayList);
    }

    public static DataMap zza(zzf zzfVar) {
        DataMap dataMap = new DataMap();
        for (zzh zzhVar : zzfVar.zzfw.zzfy) {
            zza(zzfVar.zzfx, dataMap, zzhVar.name, zzhVar.zzga);
        }
        return dataMap;
    }

    private static zzi zza(List<Asset> list, Object obj) {
        zzi zziVar = new zzi();
        if (obj == null) {
            zziVar.type = 14;
            return zziVar;
        }
        zziVar.zzgc = new zzj();
        if (obj instanceof String) {
            zziVar.type = 2;
            zziVar.zzgc.zzge = (String) obj;
        } else if (obj instanceof Integer) {
            zziVar.type = 6;
            zziVar.zzgc.zzgi = ((Integer) obj).intValue();
        } else if (obj instanceof Long) {
            zziVar.type = 5;
            zziVar.zzgc.zzgh = ((Long) obj).longValue();
        } else if (obj instanceof Double) {
            zziVar.type = 3;
            zziVar.zzgc.zzgf = ((Double) obj).doubleValue();
        } else if (obj instanceof Float) {
            zziVar.type = 4;
            zziVar.zzgc.zzgg = ((Float) obj).floatValue();
        } else if (obj instanceof Boolean) {
            zziVar.type = 8;
            zziVar.zzgc.zzgk = ((Boolean) obj).booleanValue();
        } else if (obj instanceof Byte) {
            zziVar.type = 7;
            zziVar.zzgc.zzgj = ((Byte) obj).byteValue();
        } else if (obj instanceof byte[]) {
            zziVar.type = 1;
            zziVar.zzgc.zzgd = (byte[]) obj;
        } else if (obj instanceof String[]) {
            zziVar.type = 11;
            zziVar.zzgc.zzgn = (String[]) obj;
        } else if (obj instanceof long[]) {
            zziVar.type = 12;
            zziVar.zzgc.zzgo = (long[]) obj;
        } else if (obj instanceof float[]) {
            zziVar.type = 15;
            zziVar.zzgc.zzgp = (float[]) obj;
        } else if (obj instanceof Asset) {
            zziVar.type = 13;
            zzj zzjVar = zziVar.zzgc;
            list.add((Asset) obj);
            zzjVar.zzgq = list.size() - 1;
        } else {
            int i = 0;
            if (obj instanceof DataMap) {
                zziVar.type = 9;
                DataMap dataMap = (DataMap) obj;
                TreeSet<String> treeSet = new TreeSet(dataMap.keySet());
                zzh[] zzhVarArr = new zzh[treeSet.size()];
                for (String str : treeSet) {
                    zzhVarArr[i] = new zzh();
                    zzhVarArr[i].name = str;
                    zzhVarArr[i].zzga = zza(list, dataMap.get(str));
                    i++;
                }
                zziVar.zzgc.zzgl = zzhVarArr;
            } else if (obj instanceof ArrayList) {
                zziVar.type = 10;
                ArrayList arrayList = (ArrayList) obj;
                zzi[] zziVarArr = new zzi[arrayList.size()];
                Object obj2 = null;
                int size = arrayList.size();
                int i2 = 14;
                while (i < size) {
                    Object obj3 = arrayList.get(i);
                    zzi zziVarZza = zza(list, obj3);
                    if (zziVarZza.type != 14 && zziVarZza.type != 2 && zziVarZza.type != 6 && zziVarZza.type != 9) {
                        String strValueOf = String.valueOf(obj3.getClass());
                        StringBuilder sb = new StringBuilder(String.valueOf(strValueOf).length() + TsExtractor.TS_STREAM_TYPE_HDMV_DTS);
                        sb.append("The only ArrayList element types supported by DataBundleUtil are String, Integer, Bundle, and null, but this ArrayList contains a ");
                        sb.append(strValueOf);
                        throw new IllegalArgumentException(sb.toString());
                    }
                    if (i2 == 14 && zziVarZza.type != 14) {
                        i2 = zziVarZza.type;
                        obj2 = obj3;
                    } else if (zziVarZza.type != i2) {
                        String strValueOf2 = String.valueOf(obj2.getClass());
                        String strValueOf3 = String.valueOf(obj3.getClass());
                        StringBuilder sb2 = new StringBuilder(String.valueOf(strValueOf2).length() + 80 + String.valueOf(strValueOf3).length());
                        sb2.append("ArrayList elements must all be of the sameclass, but this one contains a ");
                        sb2.append(strValueOf2);
                        sb2.append(" and a ");
                        sb2.append(strValueOf3);
                        throw new IllegalArgumentException(sb2.toString());
                    }
                    zziVarArr[i] = zziVarZza;
                    i++;
                }
                zziVar.zzgc.zzgm = zziVarArr;
            } else {
                String strValueOf4 = String.valueOf(obj.getClass().getSimpleName());
                throw new RuntimeException(strValueOf4.length() != 0 ? "newFieldValueFromValue: unexpected value ".concat(strValueOf4) : new String("newFieldValueFromValue: unexpected value "));
            }
        }
        return zziVar;
    }

    private static void zza(List<Asset> list, DataMap dataMap, String str, zzi zziVar) {
        int i = zziVar.type;
        boolean z = false;
        int i2 = 14;
        if (i == 14) {
            dataMap.putString(str, null);
            return;
        }
        zzj zzjVar = zziVar.zzgc;
        if (i == 1) {
            dataMap.putByteArray(str, zzjVar.zzgd);
            return;
        }
        if (i == 11) {
            dataMap.putStringArray(str, zzjVar.zzgn);
            return;
        }
        if (i == 12) {
            dataMap.putLongArray(str, zzjVar.zzgo);
            return;
        }
        if (i == 15) {
            dataMap.putFloatArray(str, zzjVar.zzgp);
            return;
        }
        if (i == 2) {
            dataMap.putString(str, zzjVar.zzge);
            return;
        }
        if (i == 3) {
            dataMap.putDouble(str, zzjVar.zzgf);
            return;
        }
        if (i == 4) {
            dataMap.putFloat(str, zzjVar.zzgg);
            return;
        }
        if (i == 5) {
            dataMap.putLong(str, zzjVar.zzgh);
            return;
        }
        if (i == 6) {
            dataMap.putInt(str, zzjVar.zzgi);
            return;
        }
        if (i == 7) {
            dataMap.putByte(str, (byte) zzjVar.zzgj);
            return;
        }
        if (i == 8) {
            dataMap.putBoolean(str, zzjVar.zzgk);
            return;
        }
        if (i == 13) {
            if (list != null) {
                dataMap.putAsset(str, list.get((int) zzjVar.zzgq));
                return;
            } else {
                String strValueOf = String.valueOf(str);
                throw new RuntimeException(strValueOf.length() != 0 ? "populateBundle: unexpected type for: ".concat(strValueOf) : new String("populateBundle: unexpected type for: "));
            }
        }
        int i3 = 9;
        if (i == 9) {
            DataMap dataMap2 = new DataMap();
            for (zzh zzhVar : zzjVar.zzgl) {
                zza(list, dataMap2, zzhVar.name, zzhVar.zzga);
            }
            dataMap.putDataMap(str, dataMap2);
            return;
        }
        if (i == 10) {
            int i4 = 14;
            for (zzi zziVar2 : zzjVar.zzgm) {
                if (i4 == 14) {
                    if (zziVar2.type == 9 || zziVar2.type == 2 || zziVar2.type == 6) {
                        i4 = zziVar2.type;
                    } else if (zziVar2.type != 14) {
                        int i5 = zziVar2.type;
                        StringBuilder sb = new StringBuilder(String.valueOf(str).length() + 48);
                        sb.append("Unexpected TypedValue type: ");
                        sb.append(i5);
                        sb.append(" for key ");
                        sb.append(str);
                        throw new IllegalArgumentException(sb.toString());
                    }
                } else if (zziVar2.type != i4) {
                    int i6 = zziVar2.type;
                    StringBuilder sb2 = new StringBuilder(String.valueOf(str).length() + 126);
                    sb2.append("The ArrayList elements should all be the same type, but ArrayList with key ");
                    sb2.append(str);
                    sb2.append(" contains items of type ");
                    sb2.append(i4);
                    sb2.append(" and ");
                    sb2.append(i6);
                    throw new IllegalArgumentException(sb2.toString());
                }
            }
            ArrayList<Integer> arrayList = new ArrayList<>(zzjVar.zzgm.length);
            zzi[] zziVarArr = zzjVar.zzgm;
            int length = zziVarArr.length;
            int i7 = 0;
            while (i7 < length) {
                zzi zziVar3 = zziVarArr[i7];
                if (zziVar3.type == i2) {
                    arrayList.add(z);
                } else if (i4 != i3) {
                    if (i4 == 2) {
                        arrayList.add(zziVar3.zzgc.zzge);
                    } else if (i4 == 6) {
                        arrayList.add(Integer.valueOf(zziVar3.zzgc.zzgi));
                    } else {
                        StringBuilder sb3 = new StringBuilder(39);
                        sb3.append("Unexpected typeOfArrayList: ");
                        sb3.append(i4);
                        throw new IllegalArgumentException(sb3.toString());
                    }
                } else {
                    DataMap dataMap3 = new DataMap();
                    for (zzh zzhVar2 : zziVar3.zzgc.zzgl) {
                        zza(list, dataMap3, zzhVar2.name, zzhVar2.zzga);
                    }
                    arrayList.add(dataMap3);
                }
                i7++;
                z = false;
                i2 = 14;
                i3 = 9;
            }
            if (i4 == 14) {
                dataMap.putStringArrayList(str, arrayList);
                return;
            }
            if (i4 == 9) {
                dataMap.putDataMapArrayList(str, arrayList);
                return;
            }
            if (i4 == 2) {
                dataMap.putStringArrayList(str, arrayList);
                return;
            } else {
                if (i4 == 6) {
                    dataMap.putIntegerArrayList(str, arrayList);
                    return;
                }
                StringBuilder sb4 = new StringBuilder(39);
                sb4.append("Unexpected typeOfArrayList: ");
                sb4.append(i4);
                throw new IllegalStateException(sb4.toString());
            }
        }
        StringBuilder sb5 = new StringBuilder(43);
        sb5.append("populateBundle: unexpected type ");
        sb5.append(i);
        throw new RuntimeException(sb5.toString());
    }
}
