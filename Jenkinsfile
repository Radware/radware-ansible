/* ### Jenkinsfile ###
Hey there,
I'm Jenkinsfile and I rule the build process of current repository.
I'm identical among all branches.
Editing me, could fail builds.
!!Please don't edit me unless you know what are you doing for 100%!!
If you are only 99.9% sure, consult CM team  test*/


// Define on which agent pipeline will run (branch dependent)
def agentLabel

    agentLabel = "cmslv"

// Declare dynamic library
def cmlib = library(
    identifier: 'cm_library@master',
    retriever: modernSCM([$class: 'GitSCMSource',
                          remote: 'http://bitbucket:7990/scm/cm/cm_library.git',
                          // git clone user cmjen04 credentials
                          credentialsId: 'c61b51e5-10a5-41a3-b480-6c3946624c0d'])
)


// Pipeline is starting here!
pipeline {
    environment {
        // Git repository variables:
      	// Parse project name (Parse GIT_URL or GIT_URL_1(PR build). Output is a project name in lowercase)
        projName = g_buildMeta.projName()
        // Parse repository name (Parse GIT_URL or GIT_URL_1(PR build). Output is a repository name in lowercase)
        repoName = g_buildMeta.repoName()
        // Parse repository name without a projName prefix (Remove project name prefix from repo name)
        repoNameNp = g_buildMeta.repoNameNp(repoName, projName)
        // Parse feature(or other branch type) branch name & apply lower case (Remove prefix from branch name)
        c_BRANCH_NAME = g_buildMeta.c_BRANCH_NAME()

        // Credentials variables (dependent on Jenkins server where the pipeline is executed):'
      	// git credentials (cmjen06 generated)
        gitCreds = 'c61b51e5-10a5-41a3-b480-6c3946624c0d'

        pythonImg = "3rdpkgartifactory:17111/python:3.7"

    } // environment
    agent {
        label agentLabel
    } // agent

    options {
        disableConcurrentBuilds()
        timeout(20)
      	timestamps()
        buildDiscarder logRotator(artifactDaysToKeepStr: '', artifactNumToKeepStr: '10', daysToKeepStr: env.BRANCH_NAME ==~ "master|dev" ? '60' : '15', numToKeepStr: env.BRANCH_NAME ==~ "master|dev" ? '25' : '10')
    } // options
    parameters {
        booleanParam(name: 'RELEASE_PACKAGE', defaultValue: false, description: '<br><b><font color="red">Release the python package</font></b>')
    } // parameters
    stages {
      	stage('Build project') {
            when {
       	        anyOf {
                    expression { RELEASE_PACKAGE == "false" }  //only if it isn't release
                } // anyOf
            } // when
            steps {
              println "create python package"
              sh """docker run --rm -v ${WORKSPACE}:/workspace -w /workspace ${pythonImg} /bin/bash -c "python3 tools/build_project.py && chmod 777 -R *" """
            } // steps
        } // stage Build project
        stage('Upload Package') {
            when { 
                anyOf { 
                    expression { c_BRANCH_NAME == 'create_job' }
                } // anyOf
            } // when
            steps {
                script{
                    if (RELEASE_PACKAGE == "false") {
                        withCredentials([[$class: "UsernamePasswordMultiBinding", credentialsId: "${gitCreds}", passwordVariable: "gitPass", usernameVariable: "gitUser"]]) {
                            println "Upload to test pypi server"
                        } // withCredentials

                    // upload
                    } else if (RELEASE_PACKAGE == "true") {
                        withCredentials([[$class: "UsernamePasswordMultiBinding", credentialsId: "${gitCreds}", passwordVariable: "gitPass", usernameVariable: "gitUser"]]) {
                            println "Upload to release pypi server"
                        } // withCredentials
                    } // else if
                    
                } // script
            } // steps
        } // stage Upload Package
    } // stages
    post {
        always {
            script {
                // Print environment variables
                sh "env"
            } // script
            // Send email to 'DevelopersRecipientProvider'
            emailext body: '${DEFAULT_CONTENT}', recipientProviders: [[$class: 'DevelopersRecipientProvider']], subject: '$DEFAULT_SUBJECT', to: 'GilD@radware.com'
        } // always
        success {
            // Create git tag on master & dev branches
            script {
                if (c_BRANCH_NAME == "master" || c_BRANCH_NAME == "dev") {
                    withCredentials([[$class: "UsernamePasswordMultiBinding", credentialsId: "${gitCreds}", passwordVariable: "gitPass", usernameVariable: "gitUser"]]) {
                        sh '''git tag -a "$BUILD_TAG" -m "Message of $BUILD_TAG"
                        git push http://${gitUser}:${gitPass}@bitbucket:7990/scm/${projName}/${repoName} --tag'''
                    } // withCredentials
                } // if
            } // script
        } // success
    } // post
} // pipeline
