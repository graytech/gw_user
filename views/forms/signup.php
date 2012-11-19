<script type="text/javascript">
<!--
(function ($) {

	$(document).ready(function () {
		var $signupform = $('#user-signup');
		//$signupform.hide();
		$signupform.validate({
			rules: {
				firstname: {
					required: true
				}
			}
		});
	});
})(jQuery);
//-->
</script>

<style>
	input.error { border: 1px solid red; }
	label.error {
		background: url('http://dev.jquery.com/view/trunk/plugins/validate/demo/images/unchecked.gif') no-repeat;
		padding-left: 16px;
		margin-left: .3em;
	}
	label.valid {
		background: url('http://dev.jquery.com/view/trunk/plugins/validate/demo/images/checked.gif') no-repeat;
		display: block;
		width: 16px;
		height: 16px;
	}
</style>

<div class="form signup">
<div class="signup_msg"></div>
<form class="signup" id="user-signup" method="post">
	<input type="hidden" name="formaction" value="signup-submit" />
	<fieldset>
	<div class="field firstname">
		<label for="firstname">First Name</label>
		<input type="text" id="firstname" class="firstname" name="signup[firstname]" value="" />
	</div>
	<div class="field last_name">
		<label for="last_name">Last Name</label>
		<input type="text" id="last_name" class="last_name" name="signup[last_name]" value="" />
	</div>
	<div class="field email">
		<label for="email">Email Address</label>
		<input type="text" id="email" class="email" name="signup[email]" value="" />
	</div>
	<div class="field zipcode">
		<label for="zipcode">Zip Code</label>
		<input type="text" id="zipcode" class="zipcode" name="signup[zipcode]" value="" />
	</div>
	<div class="field username">
		<label for="username">User Name</label>
		<input type="text" id="username" class="username" name="signup[username]" value="" />
	</div>
	<div class="field password">
		<label for="password">Password</label>
		<input type="password" id="password" class="password" name="signup[password]" value="" />
	</div>
	</fieldset>
	<input class="button" type="submit" value="signup" />
</form>


</div>