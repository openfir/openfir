/* SPDX-License-Identifier: Apache-2.0
 *
 * Pure C11 Android JNI bridge between OpenFIRCore.kt and libopenfir_core.so.
 * Zero third-party dependencies.
 */

#include <android/log.h>
#include <jni.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "openfir.h"

#define LOG_TAG "OpenFIRJNI"

static JavaVM *g_jvm = NULL;
static pthread_mutex_t g_cb_mu = PTHREAD_MUTEX_INITIALIZER;
static jobject g_listener_ref = NULL;
static jmethodID g_on_event_mid = NULL;

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;
    g_jvm = vm;
    return JNI_VERSION_1_6;
}

static void jni_event_trampoline(uint64_t handle, const char *json_utf8, void *user_ctx) {
    (void)user_ctx;
    if (!g_jvm || !json_utf8) return;

    pthread_mutex_lock(&g_cb_mu);
    jobject target = g_listener_ref;
    jmethodID mid = g_on_event_mid;
    if (!target || !mid) {
        pthread_mutex_unlock(&g_cb_mu);
        return;
    }

    JNIEnv *env = NULL;
    int attached = 0;
    jint r = (*g_jvm)->GetEnv(g_jvm, (void **)&env, JNI_VERSION_1_6);
    if (r == JNI_EDETACHED) {
        if ((*g_jvm)->AttachCurrentThread(g_jvm, &env, NULL) != JNI_OK) {
            pthread_mutex_unlock(&g_cb_mu);
            return;
        }
        attached = 1;
    } else if (r != JNI_OK) {
        pthread_mutex_unlock(&g_cb_mu);
        return;
    }

    jstring jstr = (*env)->NewStringUTF(env, json_utf8);
    if (jstr) {
        (*env)->CallVoidMethod(env, target, mid, (jlong)handle, jstr);
        if ((*env)->ExceptionCheck(env)) {
            (*env)->ExceptionClear(env);
        }
        (*env)->DeleteLocalRef(env, jstr);
    }

    if (attached) {
        (*g_jvm)->DetachCurrentThread(g_jvm);
    }
    pthread_mutex_unlock(&g_cb_mu);
}

JNIEXPORT void JNICALL Java_io_openfir_app_OpenFIRCore_nativeSetListener(
    JNIEnv *env, jobject thiz, jobject listener) {
    (void)thiz;
    pthread_mutex_lock(&g_cb_mu);
    if (g_listener_ref) {
        (*env)->DeleteGlobalRef(env, g_listener_ref);
        g_listener_ref = NULL;
        g_on_event_mid = NULL;
    }
    if (listener) {
        g_listener_ref = (*env)->NewGlobalRef(env, listener);
        jclass cls = (*env)->GetObjectClass(env, listener);
        g_on_event_mid = (*env)->GetMethodID(env, cls, "onCoreEvent", "(JLjava/lang/String;)V");
        (*env)->DeleteLocalRef(env, cls);
    }
    pthread_mutex_unlock(&g_cb_mu);
}

JNIEXPORT jstring JNICALL Java_io_openfir_app_OpenFIRCore_nativeVersion(JNIEnv *env, jobject thiz) {
    (void)thiz;
    const char *v = openfir_version();
    return (*env)->NewStringUTF(env, v ? v : "OpenFIR v1.1.0");
}

JNIEXPORT jstring JNICALL Java_io_openfir_app_OpenFIRCore_nativeKeygen(JNIEnv *env, jobject thiz) {
    (void)thiz;
    char buf[80];
    buf[0] = '\0';
    int n = openfir_keygen(buf, sizeof(buf));
    if (n <= 0) return (*env)->NewStringUTF(env, "");
    buf[sizeof(buf) - 1] = '\0';
    return (*env)->NewStringUTF(env, buf);
}

JNIEXPORT jlong JNICALL Java_io_openfir_app_OpenFIRCore_nativeTransferStart(
    JNIEnv *env, jobject thiz, jstring cfg_json) {
    (void)thiz;
    if (!cfg_json) return 0;
    const char *c_cfg = (*env)->GetStringUTFChars(env, cfg_json, NULL);
    if (!c_cfg) return 0;
    uint64_t h = openfir_transfer_start(c_cfg, jni_event_trampoline, NULL);
    (*env)->ReleaseStringUTFChars(env, cfg_json, c_cfg);
    return (jlong)h;
}

JNIEXPORT void JNICALL Java_io_openfir_app_OpenFIRCore_nativeTransferCancel(
    JNIEnv *env, jobject thiz, jlong handle) {
    (void)env;
    (void)thiz;
    openfir_transfer_cancel((uint64_t)handle);
}

JNIEXPORT jlong JNICALL Java_io_openfir_app_OpenFIRCore_nativeServerStart(
    JNIEnv *env, jobject thiz, jstring cfg_json) {
    (void)thiz;
    if (!cfg_json) return 0;
    const char *c_cfg = (*env)->GetStringUTFChars(env, cfg_json, NULL);
    if (!c_cfg) return 0;
    uint64_t h = openfir_server_start(c_cfg, jni_event_trampoline, NULL);
    (*env)->ReleaseStringUTFChars(env, cfg_json, c_cfg);
    return (jlong)h;
}

JNIEXPORT void JNICALL Java_io_openfir_app_OpenFIRCore_nativeServerStop(
    JNIEnv *env, jobject thiz, jlong handle) {
    (void)env;
    (void)thiz;
    openfir_server_stop((uint64_t)handle);
}

JNIEXPORT jlong JNICALL Java_io_openfir_app_OpenFIRCore_nativeSelftestStart(
    JNIEnv *env, jobject thiz) {
    (void)env;
    (void)thiz;
    return (jlong)openfir_selftest_start(jni_event_trampoline, NULL);
}
