package im.uwrkaxlmjj.tgnet;

import com.blankj.utilcode.util.GsonUtils;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.utils.apache.StringEscapeUtils;
import java.lang.reflect.Field;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes2.dex */
public class TLJsonResolve {
    public static String TAG = TLJsonResolve.class.getName();

    public static String getData(TLObject response) {
        if (response == null) {
            return null;
        }
        if (response instanceof TLRPC.TL_dataJSON) {
            String jsonData = ((TLRPC.TL_dataJSON) response).data;
            return jsonData;
        }
        Field[] fields = response.getClass().getDeclaredFields();
        for (Field f : fields) {
            if (TLRPC.TL_dataJSON.class.getName().equals(f.getType().getName())) {
                f.setAccessible(true);
                try {
                    Object o = f.get(response);
                    if (o == null) {
                        return null;
                    }
                    String jsonData2 = ((TLRPC.TL_dataJSON) o).data;
                    return jsonData2;
                } catch (IllegalAccessException e) {
                    e.printStackTrace();
                    return null;
                }
            }
        }
        return null;
    }

    public static <T> TLApiModel<T> parse(String jsonData, Class<?> clz) {
        TLRPC.TL_dataJSON dataJSON = new TLRPC.TL_dataJSON();
        dataJSON.data = jsonData;
        return parse(dataJSON, clz);
    }

    public static <T> TLApiModel<T> parse(TLObject tLObject, Class<?> cls) {
        TLApiModel<T> tLApiModel = null;
        String message = null;
        try {
            tLApiModel = (TLApiModel) GsonUtils.fromJson(getData(tLObject), TLApiModel.class);
            if (tLApiModel.data != null) {
                tLApiModel.data = StringEscapeUtils.unescapeJava(tLApiModel.data);
                if (tLApiModel.data != null) {
                    try {
                        tLApiModel.data = tLApiModel.data.replaceAll("\"\\{", "{");
                    } catch (Exception e) {
                    }
                    try {
                        tLApiModel.data = tLApiModel.data.replaceAll("}\"", "}");
                    } catch (Exception e2) {
                    }
                    try {
                        tLApiModel.data = tLApiModel.data.replaceAll("\"\\[", "[");
                    } catch (Exception e3) {
                    }
                    try {
                        tLApiModel.data = tLApiModel.data.replaceAll("]\"", "]");
                    } catch (Exception e4) {
                    }
                    if (!tLApiModel.data.startsWith("{")) {
                        if (tLApiModel.data.startsWith("[")) {
                            tLApiModel.modelList = (List) GsonUtils.fromJson(tLApiModel.data, new ParameterizedTypeImpl(cls));
                        }
                    } else {
                        tLApiModel.model = (T) GsonUtils.fromJson(tLApiModel.data, (Class) cls);
                    }
                }
            }
        } catch (Exception e5) {
            message = e5.getMessage();
            FileLog.e(TAG + " =====> " + e5.getMessage());
        }
        if (tLApiModel == null) {
            tLApiModel = new TLApiModel<>();
            tLApiModel.code = "-9999";
            if (message != null) {
                tLApiModel.message = message;
            } else {
                tLApiModel.message = LocaleController.getString("TLJsonResolveParseFaild", R.string.TLJsonResolveParseFaild);
            }
        }
        return tLApiModel;
    }

    public static <T> TLApiModel<T> parse3(TLObject tLObject, Class<?> cls) {
        TLApiModel<T> tLApiModel = null;
        String message = null;
        try {
            tLApiModel = (TLApiModel) GsonUtils.fromJson(getData(tLObject), TLApiModel.class);
            if (tLApiModel.data != null && tLApiModel.data != null) {
                if (tLApiModel.data.startsWith("{")) {
                    tLApiModel.model = (T) GsonUtils.fromJson(tLApiModel.data, (Class) cls);
                } else if (tLApiModel.data.startsWith("[")) {
                    tLApiModel.modelList = (List) GsonUtils.fromJson(tLApiModel.data, new ParameterizedTypeImpl(cls));
                }
            }
        } catch (Exception e) {
            message = e.getMessage();
            FileLog.e(TAG + " =====> " + e.getMessage());
        }
        if (tLApiModel == null) {
            tLApiModel = new TLApiModel<>();
            tLApiModel.code = "-9999";
            if (message != null) {
                tLApiModel.message = message;
            } else {
                tLApiModel.message = LocaleController.getString("TLJsonResolveParseFaild", R.string.TLJsonResolveParseFaild);
            }
        }
        return tLApiModel;
    }

    private static class ParameterizedTypeImpl implements ParameterizedType {
        Class clazz;

        public ParameterizedTypeImpl(Class clz) {
            this.clazz = clz;
        }

        @Override // java.lang.reflect.ParameterizedType
        public Type[] getActualTypeArguments() {
            return new Type[]{this.clazz};
        }

        @Override // java.lang.reflect.ParameterizedType
        public Type getRawType() {
            return List.class;
        }

        @Override // java.lang.reflect.ParameterizedType
        public Type getOwnerType() {
            return null;
        }
    }
}
