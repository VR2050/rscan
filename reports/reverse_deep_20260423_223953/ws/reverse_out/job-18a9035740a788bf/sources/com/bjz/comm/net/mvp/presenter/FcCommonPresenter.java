package com.bjz.comm.net.mvp.presenter;

import android.text.TextUtils;
import android.util.Log;
import com.android.tools.r8.annotations.SynthesizedClassMap;
import com.bjz.comm.net.BuildVars;
import com.bjz.comm.net.UrlConstant;
import com.bjz.comm.net.base.DataListener;
import com.bjz.comm.net.bean.BResponse;
import com.bjz.comm.net.bean.FcMediaResponseBean;
import com.bjz.comm.net.mvp.contract.BaseFcContract;
import com.bjz.comm.net.mvp.model.FcCommonModel;
import com.bjz.comm.net.utils.FileUtils;
import com.bjz.comm.net.utils.RxHelper;
import io.reactivex.Observable;
import io.reactivex.ObservableEmitter;
import io.reactivex.ObservableOnSubscribe;
import io.reactivex.Observer;
import io.reactivex.android.schedulers.AndroidSchedulers;
import io.reactivex.disposables.Disposable;
import io.reactivex.schedulers.Schedulers;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import okhttp3.ResponseBody;

/* JADX INFO: loaded from: classes4.dex */
public class FcCommonPresenter implements BaseFcContract.IFcCommPresenter {
    private String TAG = FcCommonPresenter.class.getSimpleName();
    BaseFcContract.IFcCommView mView;
    private FcCommonModel model;
    private String uploadUrl;

    public FcCommonPresenter(BaseFcContract.IFcCommView view) {
        this.model = null;
        this.mView = view;
        if (0 == 0) {
            this.model = new FcCommonModel();
        }
    }

    @Override // com.bjz.comm.net.base.IBPresenter
    public void unSubscribeTask() {
        this.model.unSubscribeTask();
        this.uploadUrl = null;
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommPresenter
    public void getUploadAddr(int location, final File file, final DataListener<BResponse<FcMediaResponseBean>> listener) {
        this.model.getUploadAddr(location, new DataListener<BResponse<ArrayList<String>>>() { // from class: com.bjz.comm.net.mvp.presenter.FcCommonPresenter.1
            @Override // com.bjz.comm.net.base.DataListener
            public void onResponse(BResponse<ArrayList<String>> result) {
                if (result == null) {
                    FcCommonPresenter.this.mView.getUploadUrlFailed(null);
                    return;
                }
                if (result.isState() && result.Data != null) {
                    ArrayList<String> data = result.Data;
                    if (data.size() <= 0 || TextUtils.isEmpty(data.get(0))) {
                        FcCommonPresenter.this.mView.getUploadUrlFailed(null);
                        return;
                    }
                    FcCommonPresenter.this.uploadUrl = data.get(0) + UrlConstant.PUBLISH_FILE_UPLOAD_URL;
                    FcCommonPresenter.this.uploadFile(file, listener);
                    return;
                }
                FcCommonPresenter.this.mView.getUploadUrlFailed(result.Message);
            }

            @Override // com.bjz.comm.net.base.DataListener
            public void onError(Throwable throwable) {
                FcCommonPresenter.this.mView.getUploadUrlFailed(RxHelper.getInstance().getErrorInfo(throwable));
            }
        });
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommPresenter
    public void uploadFile(File file, DataListener<BResponse<FcMediaResponseBean>> listener) {
        if (TextUtils.isEmpty(this.uploadUrl)) {
            getUploadAddr(0, file, listener);
        } else if (listener == null) {
            this.model.uploadFile(this.uploadUrl, "file", FileUtils.getInstance().getPicName(file), file, new DataListener<BResponse<FcMediaResponseBean>>() { // from class: com.bjz.comm.net.mvp.presenter.FcCommonPresenter.2
                @Override // com.bjz.comm.net.base.DataListener
                public void onResponse(BResponse<FcMediaResponseBean> result) {
                    if (result != null) {
                        if (result.isState()) {
                            FcCommonPresenter.this.mView.onUploadFileSucc(result.Data, result.Message);
                            return;
                        } else {
                            FcCommonPresenter.this.mView.onUploadFileError(result.Message);
                            return;
                        }
                    }
                    FcCommonPresenter.this.mView.onUploadFileError(null);
                }

                @Override // com.bjz.comm.net.base.DataListener
                public void onError(Throwable throwable) {
                    FcCommonPresenter.this.mView.onUploadFileError(RxHelper.getInstance().getErrorInfo(throwable));
                }
            });
        } else {
            this.model.uploadFile(this.uploadUrl, "file", FileUtils.getInstance().getPicName(file), file, listener);
        }
    }

    @Override // com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommPresenter
    public void downloadFile(String url, String dirPath, String fileName) {
        if (BuildVars.LOG_VERSION) {
            Log.d("FcDownloadPic", "downloadFile ===>  , url = " + url + " , dirPath = " + dirPath + " , fileName = " + fileName);
        }
        this.model.downloadFile(url, new AnonymousClass3(dirPath, fileName));
    }

    /* JADX INFO: renamed from: com.bjz.comm.net.mvp.presenter.FcCommonPresenter$3, reason: invalid class name */
    @SynthesizedClassMap({$$Lambda$FcCommonPresenter$3$GjRCkVOiLCeaTAYiQav8VniApvo.class})
    class AnonymousClass3 implements DataListener<ResponseBody> {
        final /* synthetic */ String val$dirPath;
        final /* synthetic */ String val$fileName;

        AnonymousClass3(String str, String str2) {
            this.val$dirPath = str;
            this.val$fileName = str2;
        }

        @Override // com.bjz.comm.net.base.DataListener
        public void onResponse(final ResponseBody result) {
            if (result != null) {
                final String str = this.val$dirPath;
                final String str2 = this.val$fileName;
                Observable.create(new ObservableOnSubscribe() { // from class: com.bjz.comm.net.mvp.presenter.-$$Lambda$FcCommonPresenter$3$GjRCkVOiLCeaTAYiQav8VniApvo
                    @Override // io.reactivex.ObservableOnSubscribe
                    public final void subscribe(ObservableEmitter observableEmitter) throws Exception {
                        this.f$0.lambda$onResponse$0$FcCommonPresenter$3(result, str, str2, observableEmitter);
                    }
                }).subscribeOn(Schedulers.io()).observeOn(AndroidSchedulers.mainThread()).subscribe(new Observer<File>() { // from class: com.bjz.comm.net.mvp.presenter.FcCommonPresenter.3.1
                    @Override // io.reactivex.Observer
                    public void onSubscribe(Disposable d) {
                    }

                    @Override // io.reactivex.Observer
                    public void onNext(File file) {
                        if (file != null) {
                            FcCommonPresenter.this.mView.onDownloadFileSucc(file);
                        } else {
                            FcCommonPresenter.this.mView.onDownloadFileError("文件保存异常");
                        }
                    }

                    @Override // io.reactivex.Observer
                    public void onError(Throwable e) {
                        FcCommonPresenter.this.mView.onDownloadFileError("文件保存异常");
                    }

                    @Override // io.reactivex.Observer
                    public void onComplete() {
                    }
                });
            }
        }

        public /* synthetic */ void lambda$onResponse$0$FcCommonPresenter$3(ResponseBody result, String dirPath, String fileName, ObservableEmitter emitter) throws Exception {
            File file = FcCommonPresenter.this.saveFile(result, dirPath, fileName);
            emitter.onNext(file);
        }

        @Override // com.bjz.comm.net.base.DataListener
        public void onError(Throwable throwable) {
            FcCommonPresenter.this.mView.onDownloadFileError(RxHelper.getInstance().getErrorInfo(throwable));
        }
    }

    public File saveFile(ResponseBody response, String dirPath, String fileName) throws IOException {
        InputStream is = null;
        byte[] buf = new byte[2048];
        FileOutputStream fos = null;
        try {
            is = response.byteStream();
            long sum = 0;
            File dir = new File(dirPath);
            if (!dir.exists()) {
                dir.mkdirs();
            }
            File file = new File(dir, fileName);
            fos = new FileOutputStream(file);
            while (true) {
                int len = is.read(buf);
                if (len == -1) {
                    break;
                }
                sum += (long) len;
                fos.write(buf, 0, len);
            }
            fos.flush();
            try {
                response.close();
                if (is != null) {
                    is.close();
                }
            } catch (IOException e) {
            }
            try {
                fos.close();
            } catch (IOException e2) {
            }
            return file;
        } finally {
        }
    }
}
