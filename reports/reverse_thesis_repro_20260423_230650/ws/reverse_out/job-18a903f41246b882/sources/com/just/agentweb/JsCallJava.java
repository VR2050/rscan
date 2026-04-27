package com.just.agentweb;

import android.os.SystemClock;
import android.text.TextUtils;
import android.util.Log;
import android.webkit.WebView;
import androidx.core.app.NotificationCompat;
import androidx.recyclerview.widget.ItemTouchHelper;
import im.uwrkaxlmjj.ui.hviews.swipelist.SlidingItemMenuRecyclerView;
import java.lang.reflect.Method;
import java.util.HashMap;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* JADX INFO: loaded from: classes3.dex */
public class JsCallJava {
    private static final String[] IGNORE_UNSAFE_METHODS = {"getClass", "hashCode", "notify", "notifyAll", "equals", "toString", "wait"};
    private static final String KEY_ARGS = "args";
    private static final String KEY_METHOD = "method";
    private static final String KEY_OBJ = "obj";
    private static final String KEY_TYPES = "types";
    private static final String MSG_PROMPT_HEADER = "AgentWeb:";
    private static final String RETURN_RESULT_FORMAT = "{\"CODE\": %d, \"result\": %s}";
    private static final String TAG = "JsCallJava";
    private Object mInterfaceObj;
    private String mInterfacedName;
    private HashMap<String, Method> mMethodsMap;
    private String mPreloadInterfaceJs;

    public JsCallJava(Object interfaceObj, String interfaceName) {
        try {
            if (TextUtils.isEmpty(interfaceName)) {
                throw new Exception("injected name can not be null");
            }
            this.mInterfaceObj = interfaceObj;
            this.mInterfacedName = interfaceName;
            this.mMethodsMap = new HashMap<>();
            Method[] methods = this.mInterfaceObj.getClass().getMethods();
            StringBuilder sb = new StringBuilder("javascript:(function(b){console.log(\"");
            sb.append(this.mInterfacedName);
            sb.append(" init begin\");var a={queue:[],callback:function(){var d=Array.prototype.slice.call(arguments,0);var c=d.shift();var e=d.shift();this.queue[c].apply(this,d);if(!e){delete this.queue[c]}}};");
            for (Method method : methods) {
                Log.i("Info", "method:" + method);
                String sign = genJavaMethodSign(method);
                if (sign != null) {
                    this.mMethodsMap.put(sign, method);
                    sb.append(String.format("a.%s=", method.getName()));
                }
            }
            sb.append("function(){var f=Array.prototype.slice.call(arguments,0);if(f.length<1){throw\"");
            sb.append(this.mInterfacedName);
            sb.append(" call result, message:miss method name\"}var e=[];for(var h=1;h<f.length;h++){var c=f[h];var j=typeof c;e[e.length]=j;if(j==\"function\"){var d=a.queue.length;a.queue[d]=c;f[h]=d}}var k = new Date().getTime();var l = f.shift();var m=prompt('");
            sb.append(MSG_PROMPT_HEADER);
            sb.append("'+JSON.stringify(");
            sb.append(promptMsgFormat("'" + this.mInterfacedName + "'", "l", "e", "f"));
            sb.append("));console.log(\"invoke \"+l+\", time: \"+(new Date().getTime()-k));var g=JSON.parse(m);if(g.CODE!=200){throw\"");
            sb.append(this.mInterfacedName);
            sb.append(" call result, CODE:\"+g.CODE+\", message:\"+g.result}return g.result};Object.getOwnPropertyNames(a).forEach(function(d){var c=a[d];if(typeof c===\"function\"&&d!==\"callback\"){a[d]=function(){return c.apply(a,[d].concat(Array.prototype.slice.call(arguments,0)))}}});b.");
            sb.append(this.mInterfacedName);
            sb.append("=a;console.log(\"");
            sb.append(this.mInterfacedName);
            sb.append(" init end\")})(window)");
            this.mPreloadInterfaceJs = sb.toString();
            sb.setLength(0);
        } catch (Exception e) {
            if (LogUtils.isDebug()) {
                Log.e(TAG, "init js result:" + e.getMessage());
            }
        }
    }

    private String genJavaMethodSign(Method method) {
        String sign = method.getName();
        Class<?>[] parameterTypes = method.getParameterTypes();
        for (String ignoreMethod : IGNORE_UNSAFE_METHODS) {
            if (ignoreMethod.equals(sign)) {
                if (LogUtils.isDebug()) {
                    Log.w(TAG, "method(" + sign + ") is unsafe, will be pass");
                    return null;
                }
                return null;
            }
        }
        for (Class<?> cls : parameterTypes) {
            if (cls == String.class) {
                sign = sign + "_S";
            } else if (cls == Integer.TYPE || cls == Long.TYPE || cls == Float.TYPE || cls == Double.TYPE) {
                sign = sign + "_N";
            } else if (cls == Boolean.TYPE) {
                sign = sign + "_B";
            } else if (cls == JSONObject.class) {
                sign = sign + "_O";
            } else if (cls == JsCallback.class) {
                sign = sign + "_F";
            } else {
                sign = sign + "_P";
            }
        }
        return sign;
    }

    public String getPreloadInterfaceJs() {
        return this.mPreloadInterfaceJs;
    }

    public String call(WebView webView, JSONObject jsonObject) {
        long time;
        if (!LogUtils.isDebug()) {
            time = 0;
        } else {
            long time2 = SystemClock.uptimeMillis();
            time = time2;
        }
        if (jsonObject != null) {
            try {
                String methodName = jsonObject.getString(KEY_METHOD);
                JSONArray argsTypes = jsonObject.getJSONArray(KEY_TYPES);
                JSONArray argsVals = jsonObject.getJSONArray(KEY_ARGS);
                int len = argsTypes.length();
                Object[] values = new Object[len];
                String sign = methodName;
                int numIndex = 0;
                for (int k = 0; k < len; k++) {
                    String currType = argsTypes.optString(k);
                    Object jSONObject = null;
                    if ("string".equals(currType)) {
                        String sign2 = sign + "_S";
                        if (!argsVals.isNull(k)) {
                            jSONObject = argsVals.getString(k);
                        }
                        values[k] = jSONObject;
                        sign = sign2;
                    } else if ("number".equals(currType)) {
                        sign = sign + "_N";
                        numIndex = (numIndex * 10) + k + 1;
                    } else if ("boolean".equals(currType)) {
                        values[k] = Boolean.valueOf(argsVals.getBoolean(k));
                        sign = sign + "_B";
                    } else if ("object".equals(currType)) {
                        String sign3 = sign + "_O";
                        if (!argsVals.isNull(k)) {
                            jSONObject = argsVals.getJSONObject(k);
                        }
                        values[k] = jSONObject;
                        sign = sign3;
                    } else if ("function".equals(currType)) {
                        try {
                            String sign4 = sign + "_F";
                            values[k] = new JsCallback(webView, this.mInterfacedName, argsVals.getInt(k));
                            sign = sign4;
                        } catch (Exception e) {
                            e = e;
                            LogUtils.safeCheckCrash(TAG, NotificationCompat.CATEGORY_CALL, e);
                            if (e.getCause() != null) {
                                return getReturn(jsonObject, SlidingItemMenuRecyclerView.DEFAULT_ITEM_SCROLL_DURATION, "method execute result:" + e.getCause().getMessage(), time);
                            }
                            return getReturn(jsonObject, SlidingItemMenuRecyclerView.DEFAULT_ITEM_SCROLL_DURATION, "method execute result:" + e.getMessage(), time);
                        }
                    } else {
                        sign = sign + "_P";
                    }
                }
                Method currMethod = this.mMethodsMap.get(sign);
                if (currMethod == null) {
                    return getReturn(jsonObject, SlidingItemMenuRecyclerView.DEFAULT_ITEM_SCROLL_DURATION, "not found method(" + sign + ") with valid parameters", time);
                }
                if (numIndex > 0) {
                    Class<?>[] parameterTypes = currMethod.getParameterTypes();
                    while (numIndex > 0) {
                        int currIndex = (numIndex - ((numIndex / 10) * 10)) - 1;
                        Class<?> cls = parameterTypes[currIndex];
                        if (cls == Integer.TYPE) {
                            values[currIndex] = Integer.valueOf(argsVals.getInt(currIndex));
                        } else if (cls == Long.TYPE) {
                            values[currIndex] = Long.valueOf(Long.parseLong(argsVals.getString(currIndex)));
                        } else {
                            values[currIndex] = Double.valueOf(argsVals.getDouble(currIndex));
                        }
                        numIndex /= 10;
                    }
                }
                return getReturn(jsonObject, ItemTouchHelper.Callback.DEFAULT_DRAG_ANIMATION_DURATION, currMethod.invoke(this.mInterfaceObj, values), time);
            } catch (Exception e2) {
                e = e2;
            }
        } else {
            return getReturn(jsonObject, SlidingItemMenuRecyclerView.DEFAULT_ITEM_SCROLL_DURATION, "call data empty", time);
        }
    }

    private String getReturn(JSONObject reqJson, int stateCode, Object result, long time) {
        String insertRes;
        if (result == null) {
            insertRes = "null";
        } else if (result instanceof String) {
            insertRes = "\"".concat(String.valueOf(((String) result).replace("\"", "\\\""))).concat("\"");
        } else {
            insertRes = String.valueOf(result);
        }
        String resStr = String.format(RETURN_RESULT_FORMAT, Integer.valueOf(stateCode), insertRes);
        if (LogUtils.isDebug()) {
            Log.d(TAG, "call time: " + (SystemClock.uptimeMillis() - time) + ", request: " + reqJson + ", result:" + resStr);
        }
        return resStr;
    }

    private static String promptMsgFormat(String object, String method, String types, String args) {
        return "{" + KEY_OBJ + com.king.zxing.util.LogUtils.COLON + object + "," + KEY_METHOD + com.king.zxing.util.LogUtils.COLON + method + "," + KEY_TYPES + com.king.zxing.util.LogUtils.COLON + types + "," + KEY_ARGS + com.king.zxing.util.LogUtils.COLON + args + "}";
    }

    static boolean isSafeWebViewCallMsg(String message) {
        return message.startsWith(MSG_PROMPT_HEADER);
    }

    static JSONObject getMsgJSONObject(String message) {
        try {
            JSONObject jsonObject = new JSONObject(message.substring(MSG_PROMPT_HEADER.length()));
            return jsonObject;
        } catch (JSONException e) {
            e.printStackTrace();
            JSONObject jsonObject2 = new JSONObject();
            return jsonObject2;
        }
    }

    static String getInterfacedName(JSONObject jsonObject) {
        return jsonObject.optString(KEY_OBJ);
    }
}
