package com.bjz.comm.net.mvp.model;

import com.android.tools.r8.annotations.SynthesizedClassMap;
import com.bjz.comm.net.UrlConstant;
import com.bjz.comm.net.base.DataListener;
import com.bjz.comm.net.bean.BResponse;
import com.bjz.comm.net.bean.FcMediaResponseBean;
import com.bjz.comm.net.bean.IPResponse;
import com.bjz.comm.net.factory.ApiFactory;
import com.bjz.comm.net.mvp.contract.BaseFcContract;
import com.bjz.comm.net.utils.RxHelper;
import io.reactivex.Observable;
import io.reactivex.functions.Consumer;
import java.io.File;
import java.io.UnsupportedEncodingException;
import java.net.FileNameMap;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.util.ArrayList;
import okhttp3.MediaType;
import okhttp3.MultipartBody;
import okhttp3.RequestBody;
import okhttp3.ResponseBody;

/* JADX INFO: loaded from: classes4.dex */
@SynthesizedClassMap({$$Lambda$15kGZKH6eZ4hpDsvHURgNsylfw8.class, $$Lambda$77dzvAKl1g9CDlxEuR3k6XzTbI.class, $$Lambda$mSGpaT9jJInhBATBTFCU4D9tp7s.class, $$Lambda$ocxj43lUtA9VFMIsrwq9eDl1sCM.class})
public class FcCommonModel implements BaseFcContract.IFcCommModel {
    private static final String TAG = FcCommonModel.class.getSimpleName();

    @Override // com.bjz.comm.net.base.IBModel
    public void unSubscribeTask() {
        RxHelper.getInstance().lambda$sendSimpleRequest$0$RxHelper(TAG);
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommModel
    @Deprecated
    public void getIpLocation(final DataListener<IPResponse> listener) {
        Observable<IPResponse> observable = ApiFactory.getInstance().getApiCommon().getIpLocation(UrlConstant.GET_IP_LOCATION);
        RxHelper rxHelper = RxHelper.getInstance();
        String str = TAG;
        listener.getClass();
        Consumer consumer = new Consumer() { // from class: com.bjz.comm.net.mvp.model.-$$Lambda$ocxj43lUtA9VFMIsrwq9eDl1sCM
            @Override // io.reactivex.functions.Consumer
            public final void accept(Object obj) {
                listener.onResponse((IPResponse) obj);
            }
        };
        listener.getClass();
        rxHelper.sendCommRequest(str, observable, consumer, new $$Lambda$77dzvAKl1g9CDlxEuR3k6XzTbI(listener));
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommModel
    public void getUploadAddr(int location, DataListener<BResponse<ArrayList<String>>> listener) {
        Observable<BResponse<ArrayList<String>>> observable = ApiFactory.getInstance().getApiCommon().getUploadAddr(location);
        RxHelper rxHelper = RxHelper.getInstance();
        String str = TAG;
        listener.getClass();
        $$Lambda$mSGpaT9jJInhBATBTFCU4D9tp7s __lambda_msgpat9jjinhbatbtfcu4d9tp7s = new $$Lambda$mSGpaT9jJInhBATBTFCU4D9tp7s(listener);
        listener.getClass();
        rxHelper.sendRequest(str, observable, __lambda_msgpat9jjinhbatbtfcu4d9tp7s, new $$Lambda$77dzvAKl1g9CDlxEuR3k6XzTbI(listener));
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommModel
    public void uploadFile(String url, String formKey, String name, File file, DataListener<BResponse<FcMediaResponseBean>> listener) {
        RequestBody fileBody = RequestBody.create(MediaType.parse(guessMimeType(file.getName())), file);
        RequestBody requestBody = new MultipartBody.Builder().setType(MultipartBody.FORM).addFormDataPart("name", name).addFormDataPart(formKey, file.getName(), fileBody).build();
        Observable<BResponse<FcMediaResponseBean>> observable = ApiFactory.getInstance().getApiCommon().uploadFile(url, requestBody);
        RxHelper rxHelper = RxHelper.getInstance();
        String str = TAG;
        listener.getClass();
        $$Lambda$mSGpaT9jJInhBATBTFCU4D9tp7s __lambda_msgpat9jjinhbatbtfcu4d9tp7s = new $$Lambda$mSGpaT9jJInhBATBTFCU4D9tp7s(listener);
        listener.getClass();
        rxHelper.sendCommRequest(str, observable, __lambda_msgpat9jjinhbatbtfcu4d9tp7s, new $$Lambda$77dzvAKl1g9CDlxEuR3k6XzTbI(listener));
    }

    private String guessMimeType(String path) {
        FileNameMap fileNameMap = URLConnection.getFileNameMap();
        String contentTypeFor = null;
        try {
            contentTypeFor = fileNameMap.getContentTypeFor(URLEncoder.encode(path, "UTF-8"));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        if (contentTypeFor == null) {
            return "application/octet-stream";
        }
        return contentTypeFor;
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommModel
    public void downloadFile(String url, final DataListener<ResponseBody> listener) {
        Observable<ResponseBody> observable = ApiFactory.getInstance().getApiCommon().downloadImg(url);
        RxHelper rxHelper = RxHelper.getInstance();
        String str = TAG;
        listener.getClass();
        Consumer consumer = new Consumer() { // from class: com.bjz.comm.net.mvp.model.-$$Lambda$15kGZKH6eZ4hpDsvHURgNsylfw8
            @Override // io.reactivex.functions.Consumer
            public final void accept(Object obj) {
                listener.onResponse((ResponseBody) obj);
            }
        };
        listener.getClass();
        rxHelper.sendCommRequest(str, observable, consumer, new $$Lambda$77dzvAKl1g9CDlxEuR3k6XzTbI(listener));
    }
}
