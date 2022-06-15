#!/usr/bin/env python3

# BSD-3-Clause
# Copyright (c) Facebook, Inc. and its affiliates.
# Copyright (c) tig <https://6fx.eu/>.
# Copyright (c) Gusto, Inc.
#
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import argparse
import json
import logging
import os
import plistlib
import requests
import subprocess
import sys

from datetime import datetime
from pathlib import Path

OVERRIDES_DIR = os.path.relpath("overrides/")
RECIPE_TO_RUN = os.environ.get("RECIPE", None)


class Logger:
    def __init__(self, level=None):
        self.level = level if level is not None else "INFO"

    def _leveler(self):
        opts = {
            "INFO": logging.INFO,
            "CRITICAL": logging.CRITICAL,
            "DEBUG": logging.DEBUG,
            "WARNING": logging.WARNING,
        }
        level = self.level.upper()
        if level not in opts:
            return logging.INFO

        return opts[level]

    def logger(self):
        stdout_handler = logging.StreamHandler(sys.stdout)
        handlers = [stdout_handler]

        logging.basicConfig(
            level=logging.INFO,
            format="[%(asctime)s] {%(filename)s:%(lineno)d} %(levelname)s - %(message)s",
            handlers=handlers,
        )

        return logging.getLogger(__file__)


log = Logger().logger()


class Recipe:
    def __init__(self, path):
        self.path = os.path.join(path)
        self.error = False
        self.results = {}
        self.updated = False
        self.verified = None
        self.autopkg_repo = None
        self.overrides = OVERRIDES_DIR
        self.munki_repo = None

        self._keys = None
        self._has_run = False

    @property
    def plist(self):
        if self._keys is None:
            with open(
                os.path.join(self.autopkg_repo, self.overrides, self.path), "rb"
            ) as f:
                self._keys = plistlib.load(f)

        return self._keys

    @property
    def branch(self):
        return (
            "{}_{}".format(self.name, self.updated_version)
            .strip()
            .replace(" ", "")
            .replace(")", "-")
            .replace("(", "-")
        )

    @property
    def updated_version(self):
        if not self.results or not self.results["imported"]:
            return None

        return self.results["imported"][0]["version"].strip().replace(" ", "")

    @property
    def name(self):
        return self.plist["Input"]["NAME"]

    def set_config(self, autopkg_repo, munki_repo):
        self.autopkg_repo = autopkg_repo
        self.munki_repo = munki_repo

    def verify_trust_info(self):
        cmd = ["/usr/local/bin/autopkg", "verify-trust-info", self.path, "-vvv"]
        cmd = " ".join(cmd)

        log.info(f"Running: {str(cmd)}")

        p = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True
        )
        (_, err) = p.communicate()
        p_status = p.wait()
        if p_status == 0:
            log.info(f"{self.path} is verified")
            self.verified = True
        else:
            err = err.decode()
            self.results["message"] = err
            self.verified = False
        return self.verified

    def update_trust_info(self):
        cmd = ["/usr/local/bin/autopkg", "update-trust-info", self.path]
        cmd = " ".join(cmd)

        log.info(f"Running: {str(cmd)}")

        # Fail loudly if this exits 0
        try:
            subprocess.check_call(cmd, shell=True)
        except subprocess.CalledProcessError as e:
            log.warning(e.stderr)
            raise e

    def _parse_report(self, report):
        with open(report, "rb") as f:
            report_data = plistlib.load(f)

        failed_items = report_data.get("failures", [])
        imported_items = []
        if report_data["summary_results"]:
            # This means something happened
            munki_results = report_data["summary_results"].get(
                "munki_importer_summary_result", {}
            )
            imported_items.extend(munki_results.get("data_rows", []))

        return {"imported": imported_items, "failed": failed_items}

    def run(self):
        if self.verified is False:
            self.error = True
            self.results["failed"] = True
            self.results["imported"] = ""
        else:
            report = "/tmp/autopkg.plist"
            if not os.path.isfile(report):
                # Letting autopkg create them has led to errors on github runners
                log.info("creating report file")
                Path(report).touch()

            try:
                cmd = [
                    "/usr/local/bin/autopkg",
                    "run",
                    self.path,
                    "-vv",
                    "--post",
                    "io.github.hjuutilainen.VirusTotalAnalyzer/VirusTotalAnalyzer",
                    "--report-plist",
                    report,
                ]
                cmd = " ".join(cmd)
                log.info(f"Running: {str(cmd)}")

                subprocess.check_call(cmd, shell=True)

            except subprocess.CalledProcessError:
                self.error = True

            self._has_run = True
            self.results = self._parse_report(report)
            if not self.results["failed"] and not self.error and self.updated_version:
                self.updated = True

        return self.results


class Runner:
    def __init__(self, autopkg_repo, munki_repo, open_pr, slack_webhook):
        self.autopkg_repo = autopkg_repo
        self.munki_repo = munki_repo
        self.slack_webhook = slack_webhook
        self.pr = open_pr

    ### GIT FUNCTIONS
    def git_run(self, cmd):
        cmd = ["git"] + cmd

        log.info(f"Running: {str(cmd)}")
        hide_cmd_output = False

        try:
            result = subprocess.run(
                " ".join(cmd), shell=True, cwd=self.munki_repo, capture_output=False
            )
            log.info(f"git_run result: {result}")

        except subprocess.CalledProcessError as e:
            log.info(e.stderr)
            raise e

    def current_branch(self):
        self.git_run(["rev-parse", "--abbrev-ref", "HEAD"])

    def checkout(self, branch, new=True):
        if self.current_branch() != "main" and branch != "main":
            self.checkout("main", new=False)

        gitcmd = ["checkout"]
        if new:
            gitcmd += ["-b"]

        gitcmd.append(branch)
        # Lazy branch exists check
        try:
            self.git_run(gitcmd)
        except subprocess.CalledProcessError as e:
            if new:
                self.checkout(branch, new=False)
            else:
                raise e

    ### Recipe handling
    def handle_recipe(self, recipe, opts):
        recipe.set_config(
            autopkg_repo=self.autopkg_repo,
            munki_repo=self.munki_repo,
        )
        if not opts.disable_verification:
            recipe.verify_trust_info()
            if recipe.verified is False:
                recipe.update_trust_info()
        if recipe.verified in (True, None):
            recipe.run()
            if recipe.results["imported"]:
                self.checkout(recipe.branch)
                for imported in recipe.results["imported"]:
                    self.git_run(
                        [
                            "add",
                            f"'pkgs/{ imported['pkg_repo_path'] }'",
                        ]
                    )
                    self.git_run(
                        [
                            "add",
                            f"'pkgsinfo/{ imported['pkginfo_path'] }'",
                        ]
                    )
                self.git_run(
                    [
                        "commit",
                        "-m",
                        f"'Updated { recipe.name } to { recipe.updated_version }'",
                    ]
                )
                self.git_run(["push", "--set-upstream", "origin", recipe.branch])
                if self.pr:
                    self.open_pr(recipe, opts)
        return recipe

    def open_pr(self, recipe, opts):
        log.info(f"opening pr for {recipe.branch}")
        cmd = [
            "hub",
            "pull-request",
            "-b",
            "main",
            "-h",
            recipe.branch,
            "-m",
            f"'Updated { recipe.name } to { recipe.updated_version }'",
        ]
        os.environ["GITHUB_TOKEN"] = opts.token
        proc = subprocess.Popen(
            cmd,
            cwd=self.munki_repo,
            shell=False,
            bufsize=-1,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        output, rcode = proc.communicate(), proc.returncode

        log.info(f"opening pr result: {output} return code: {rcode}")

    def parse_recipes(self, recipes):
        recipe_list = []
        ## Added this section so that we can run individual recipes
        if RECIPE_TO_RUN:
            for recipe in recipes:
                ext = os.path.splitext(recipe)[1]
                if ext != ".recipe":
                    recipe_list.append(recipe + ".recipe")
                else:
                    recipe_list.append(recipe)
        else:
            ext = os.path.splitext(recipes)[1]
            if ext == ".json":
                parser = json.load
            elif ext == ".plist":
                parser = plistlib.load
            else:
                log.info(
                    f'Invalid run list extension "{ ext }" (expected plist or json)'
                )
                sys.exit(1)

            with open(recipes, "rb") as f:
                recipe_list = parser(f)

        return map(Recipe, recipe_list)

    ## Icon handling
    def import_icons(self):
        branch_name = f'icon_import_{datetime.now().strftime("%Y-%m-%d")}'
        self.checkout(branch_name)
        subprocess.check_call("/usr/local/munki/iconimporter munki-repo", shell=True)
        self.git_run(["add", "icons/"])
        self.git_run(["commit", "-m", "Added new icons"])
        self.git_run(["push", "--set-upstream", "origin", f"{branch_name}"])

    def slack_alert(self, recipe):
        if self.slack_webhook is None:
            log.info("Skipping slack notification - webhook is missing!")
            return

        if not recipe.verified:
            task_title = f"{ recipe.name } failed trust verification"
            task_description = recipe.results["message"]
        elif recipe.error:
            task_title = f"Failed to import { recipe.name }"
            if not recipe.results["failed"]:
                task_description = "Unknown error"
            else:
                task_description = f'Error: {recipe.results["failed"][0]["message"]}\n Traceback: {recipe.results["failed"][0]["traceback"]}\n'

                if "No releases found for repo" in task_description:
                    # Just no updates
                    return
        elif recipe.updated:
            task_title = "Imported %s %s" % (recipe.name, str(recipe.updated_version))
            task_description = (
                "*Catalogs:* %s \n" % recipe.results["imported"][0]["catalogs"]
                + "*Package Path:* `%s` \n"
                % recipe.results["imported"][0]["pkg_repo_path"]
                + "*Pkginfo Path:* `%s` \n"
                % recipe.results["imported"][0]["pkginfo_path"]
            )
        else:
            # Also no updates
            return

        response = requests.post(
            self.slack_webhook,
            data=json.dumps(
                {
                    "attachments": [
                        {
                            "username": "Autopkg",
                            "as_user": True,
                            "title": task_title,
                            "color": "warning"
                            if not recipe.verified
                            else "good"
                            if not recipe.error
                            else "danger",
                            "text": task_description,
                            "mrkdwn_in": ["text"],
                        }
                    ]
                }
            ),
            headers={"Content-Type": "application/json"},
        )
        if response.status_code != 200:
            raise ValueError(
                "Request to slack returned an error %s, the response is:\n%s"
                % (response.status_code, response.text)
            )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-a",
        "--autopkgrepo",
        help="Path to git repo. Defaults to AUTOPKG_REPO from Autopkg preferences.",
        default="",
        required=False,
    )
    parser.add_argument(
        "-d",
        "--debug",
        default="INFO",
        help="Verbosity level for logging.",
        required=False,
    )
    parser.add_argument(
        "-i",
        "--icons",
        action="store_true",
        help="Run iconimporter against git munki repo.",
        required=False,
    )
    parser.add_argument(
        "-l",
        "--list",
        help="Path to a plist or JSON list of recipe names.",
        required=True,
    )
    parser.add_argument(
        "-m",
        "--munkirepo",
        default="",
        help="Path to munki git repo. Defaults to MUNKI_REPO from Autopkg preferences.",
        required=False,
    )
    parser.add_argument(
        "-s",
        "--slack",
        default=None,
        help="Slack Webhook URL",
        required=False,
    )
    parser.add_argument(
        "-p",
        "--pr",
        action="store_true",
        help="Open a PR for imported items",
        required=False,
    )
    parser.add_argument(
        "-t",
        "--token",
        help="Github Token",
        required=False,
    )
    parser.add_argument(
        "-v",
        "--disable_verification",
        action="store_true",
        help="Disables recipe verification.",
        required=False,
    )

    args = parser.parse_args()

    failures = []
    log = Logger(level=args.debug).logger()

    recipes = (
        RECIPE_TO_RUN.split(", ") if RECIPE_TO_RUN else args.list if args.list else None
    )
    if recipes is None:
        log.info("Recipe --list or RECIPE_TO_RUN not provided!")
        sys.exit(1)
    run = Runner(
        autopkg_repo=args.autopkgrepo,
        munki_repo=args.munkirepo,
        open_pr=args.pr,
        slack_webhook=args.slack,
    )
    recipes = run.parse_recipes(recipes)

    for recipe in recipes:
        run.handle_recipe(recipe, args)
        run.slack_alert(recipe)
        if not args.disable_verification:
            if not recipe.verified:
                failures.append(recipe)
    if not args.disable_verification:
        if failures:
            title = " ".join([f"{recipe.name}" for recipe in failures])
            lines = [f"{recipe.results['message']}\n" for recipe in failures]
            with open("pull_request_title", "a+") as title_file:
                title_file.write(f"Update trust for {title}")
            with open("pull_request_body", "a+") as body_file:
                body_file.writelines(lines)

    if args.icons:
        run.import_icons()


if __name__ == "__main__":
    main()
