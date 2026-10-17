//
// Created by luoyesiqiu
//

#ifndef DPT_ANDROID_CONTENT_PM_APPLICATIONINFO_H
#define DPT_ANDROID_CONTENT_PM_APPLICATIONINFO_H

#include "dpt_reflect.h"

namespace dpt::reflect {
        class android_content_pm_ApplicationInfo: public Reflect {
        private:
            jni::JNINativeField source_dir_field = {"sourceDir","Ljava/lang/String;"};
            jni::JNINativeField data_dir_field = {"dataDir","Ljava/lang/String;"};
            jni::JNINativeField class_name_field = {"className","Ljava/lang/String;"};
            jni::JNINativeField package_name_field = {"packageName","Ljava/lang/String;"};
        public:
            android_content_pm_ApplicationInfo(JNIEnv *env,jobject obj){
                this->m_env = env;
                this->m_obj = obj;
            }
            jstring getSourceDir();
            jstring getDataDir();
            jstring getPackageName();
            void setClassName(jobject className);
        protected:
            const char * getClassName() override {
                return "android/content/pm/ApplicationInfo";
            }
        };

    } // reflect

#endif //DPT_ANDROID_CONTENT_PM_APPLICATIONINFO_H
