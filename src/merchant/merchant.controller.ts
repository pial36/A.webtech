import {
  Body,
  Controller,
  Get,
  HttpStatus,
  InternalServerErrorException,
  Post,
  UseGuards,
  UsePipes,
  ValidationPipe,
  Request,
  Put,
  NotFoundException,
  Delete,
  Param,
  ParseIntPipe,
  BadRequestException,
  UseInterceptors,
  UploadedFile,
  Res,
  HttpCode,
} from '@nestjs/common';
import { MerchantService } from './merchant.service';
import {
  ForgetPasswordDTO,
  OTP_ReceiverDTO,
  Merchant_ProfileDTO,
  MerchantDto,
  Payment_ReceiverDTO,
} from './merchant.dto';
import { JwtService } from '@nestjs/jwt';
import { AuthGuard } from './auth/auth.guard';
import { FileInterceptor } from '@nestjs/platform-express';
import { diskStorage, MulterError } from 'multer';

@Controller('api/merchant')
export class MerchantController {
  constructor(
    private readonly merchantService: MerchantService,
    private readonly jwtService: JwtService,
  ) {
    // Empty Constructor
  }

  @Get('/index')
  @UseGuards(AuthGuard)
  @UsePipes(new ValidationPipe())
  @HttpCode(HttpStatus.OK) // Set the status code to 200 (OK)
  getIndex(): any {
    return 'Relax! Merchant is Alive.';
  }
  @Get('/merchant_service')
  @UseGuards(AuthGuard)
  @UsePipes(new ValidationPipe())
  @HttpCode(HttpStatus.OK) // Set the status code to 200 (OK)
  getService(): any {
    return this.merchantService.get_service();
  }

  //   ################################################################# FEATURES ################################################################

  //   #1

  /**
   * This function Signup.
   * @param {MerchantDto} x - The first number.
   * @returns {any} The sum of x and y.
   */

  //region Authentication

  @Post('/signup/merchant_details')
  @UsePipes(new ValidationPipe())
  @HttpCode(HttpStatus.OK) // Set the status code to 200 (OK)
  async merchant_Details_Create(
    @Body() merchant_info: MerchantDto,
  ): Promise<any> {
    try {
      const saved_merchant =
        await this.merchantService.Create_Merchant(merchant_info);
      if (saved_merchant > 0) {
        return saved_merchant;
      } else {
        throw new InternalServerErrorException(
          'merchant data could not be saved',
        );
      }
    } catch (e) {
      throw new InternalServerErrorException({
        status: HttpStatus.INTERNAL_SERVER_ERROR,
        message: e.message,
      });
    }
  }

  //endregion

  //   #2
  @Get('/profile')
  @UseGuards(AuthGuard)
  @HttpCode(HttpStatus.OK) // Set the status code to 200 (OK)
  async View_own_Profile(@Request() req): Promise<any> {
    try {
      return await this.merchantService.Find_Merchant_By_Email(req.user.email);
    } catch (e) {
      throw new InternalServerErrorException(e.message);
    }
  }

  //   #3
  @Put('/profile/update')
  @UseGuards(AuthGuard)
  @UsePipes(new ValidationPipe())
  @HttpCode(HttpStatus.OK) // Set the status code to 200 (OK)
  async Update_own_Profile(
    @Request() req,
    @Body() updated_data: Merchant_ProfileDTO,
  ): Promise<any> {
    try {
      return await this.merchantService.Update_Own_Profile_Details(
        req.user.email,
        updated_data,
      );
    } catch (e) {
      throw new InternalServerErrorException(e.message);
    }
  }

  // # : Upload & Update Merchant Image
  @Put('/profile/upload')
  @UseGuards(AuthGuard)
  @HttpCode(HttpStatus.OK) // Set the status code to 200 (OK)
  @UseInterceptors(
    FileInterceptor('myfile', {
      fileFilter: (req, file, cb) => {
        if (file.originalname.match(/^.*\.(jpg|webp|png|jpeg)$/))
          cb(null, true);
        else {
          cb(new MulterError('LIMIT_UNEXPECTED_FILE', 'image'), false);
        }
      },
      limits: { fileSize: 5000000 }, // 5 MB
      storage: diskStorage({
        destination: './uploaded_pic/profile_images',
        filename: function (req, file, cb) {
          cb(null, Date.now() + file.originalname);
        },
      }),
    }),
  )
  async UploadProfileImage(
    @Request() req,
    @UploadedFile() myfileobj: Express.Multer.File,
  ): Promise<any> {
    console.log(myfileobj); // We can find the file name here
    if (myfileobj == null) {
      throw new BadRequestException({
        status: HttpStatus.BAD_REQUEST,
        message: 'Please Upload Image',
      });
    }
    const seller = await this.merchantService.Update_Profile_Picture(
      req.user.email,
      myfileobj.filename,
    );
    if (seller != null) {
      return seller;
    } else {
      throw new NotFoundException({
        status: HttpStatus.NOT_FOUND,
        message: 'No Seller Found to Upload Seller Image',
      });
    }
  }

  @Get('/profile/view_profile_image')
  @UseGuards(AuthGuard)
  @HttpCode(HttpStatus.OK) // Set the status code to 200 (OK)
  async getSellerImages(@Request() req, @Res() res): Promise<any> {
    try {
      return this.merchantService.Get_Profile_Picture(req.user.email, res);
    } catch (e) {
      throw new InternalServerErrorException(e.message);
    }
  }

  @Post('/send_money')
  @UseGuards(AuthGuard)
  @UsePipes(new ValidationPipe())
  @HttpCode(HttpStatus.OK) // Set the status code to 200 (OK)
  async Create_Billing(
    @Request() req,
    @Body() bill: Payment_ReceiverDTO,
  ): Promise<any> {
    try {
      const user_validity_decision = await this.merchantService.user_validity(
        req.user.email,
        bill.password,
      );

      if (user_validity_decision) {
        bill.payment_type = 'Send Money';
        const decision = await this.merchantService.Subtract_Credits_Amount(
          req.user.email,
          bill,
        );

        if (decision > 0) {
          return {
            success: true,
            message: 'Money has been transferred successfully',
          };
        } else {
          throw new InternalServerErrorException(
            'Payment Could not be completed',
          );
        }
      } else {
        throw new BadRequestException('Password did not matched!');
      }
    } catch (e) {
      throw new InternalServerErrorException(
        'Merchant Controller Create Billing Error = ' + e.message,
      );
    }
  }

  @Post('/cash_out')
  @UseGuards(AuthGuard)
  @UsePipes(new ValidationPipe())
  @HttpCode(HttpStatus.OK) // Set the status code to 200 (OK)
  async Cash_Out(
    @Request() req,
    @Body() bill: Payment_ReceiverDTO,
  ): Promise<any> {
    try {
      const user_validity_decision = await this.merchantService.user_validity(
        req.user.email,
        bill.password,
      );

      if (user_validity_decision) {
        bill.payment_type = 'Cash Out';
        const decision = await this.merchantService.Subtract_Credits_Amount(
          req.user.email,
          bill,
        );

        if (decision > 0) {
          return {
            success: true,
            message: 'Money has been transferred successfully',
          };
        } else {
          throw new InternalServerErrorException(
            'Payment Could not be completed',
          );
        }
      } else {
        throw new BadRequestException('Password did not matched!');
      }
    } catch (e) {
      throw new InternalServerErrorException(
        'Merchant Controller Create Billing Error = ' + e.message,
      );
    }
  }

  @Post('/bill_payment')
  @UseGuards(AuthGuard)
  @UsePipes(new ValidationPipe())
  @HttpCode(HttpStatus.OK) // Set the status code to 200 (OK)
  async Bill_Payment(
    @Request() req,
    @Body() bill: Payment_ReceiverDTO,
  ): Promise<any> {
    try {
      const user_validity_decision = await this.merchantService.user_validity(
        req.user.email,
        bill.password,
      );

      if (user_validity_decision) {
        bill.payment_type = 'Bill Payment';
        const decision = await this.merchantService.Subtract_Credits_Amount(
          req.user.email,
          bill,
        );

        if (decision > 0) {
          return {
            success: true,
            message: 'Money has been transferred successfully',
          };
        } else {
          throw new InternalServerErrorException(
            'Payment Could not be completed',
          );
        }
      } else {
        throw new BadRequestException('Password did not matched!');
      }
    } catch (e) {
      throw new InternalServerErrorException(
        'Merchant Controller Create Billing Error = ' + e.message,
      );
    }
  }

  @Post('/pay_in')
  @UseGuards(AuthGuard)
  @UsePipes(new ValidationPipe())
  @HttpCode(HttpStatus.OK) // Set the status code to 200 (OK)
  async Pay_In(
    @Request() req,
    @Body() bill: Payment_ReceiverDTO,
  ): Promise<any> {
    try {
      const user_validity_decision = await this.merchantService.user_validity(
        req.user.email,
        bill.password,
      );

      if (user_validity_decision) {
        bill.payment_type = 'Payment';
        const decision = await this.merchantService.Add_Credits_Amount(
          req.user.email,
          bill,
        );

        if (decision > 0) {
          return {
            success: true,
            message: 'Money has been transferred successfully',
          };
        } else {
          throw new InternalServerErrorException(
            'Payment Could not be completed',
          );
        }
      } else {
        throw new BadRequestException('Password did not matched!');
      }
    } catch (e) {
      throw new InternalServerErrorException(
        'Merchant Controller Create Billing Error = ' + e.message,
      );
    }
  }

  @Post('/add_money/wallet_to_bank')
  @UseGuards(AuthGuard)
  @UsePipes(new ValidationPipe())
  @HttpCode(HttpStatus.OK) // Set the status code to 200 (OK)
  async Wallet_to_Bank(
    @Request() req,
    @Body() bill: Payment_ReceiverDTO,
  ): Promise<any> {
    try {
      const user_validity_decision = await this.merchantService.user_validity(
        req.user.email,
        bill.password,
      );

      if (user_validity_decision) {
        bill.payment_type = 'Wallet to Bank';
        const decision = await this.merchantService.Subtract_Credits_Amount(
          req.user.email,
          bill,
        );

        if (decision > 0) {
          return {
            success: true,
            message: 'Money has been transferred successfully',
          };
        } else {
          throw new InternalServerErrorException(
            'Payment Could not be completed',
          );
        }
      } else {
        throw new BadRequestException('Password did not matched!');
      }
    } catch (e) {
      throw new InternalServerErrorException(
        'Merchant Controller Create Billing Error = ' + e.message,
      );
    }
  }

  @Post('/add_money/wallet_to_card')
  @UseGuards(AuthGuard)
  @UsePipes(new ValidationPipe())
  @HttpCode(HttpStatus.OK) // Set the status code to 200 (OK)
  async Wallet_to_Card(
    @Request() req,
    @Body() bill: Payment_ReceiverDTO,
  ): Promise<any> {
    try {
      const user_validity_decision = await this.merchantService.user_validity(
        req.user.email,
        bill.password,
      );

      if (user_validity_decision) {
        bill.payment_type = 'Wallet to Card';
        const decision = await this.merchantService.Subtract_Credits_Amount(
          req.user.email,
          bill,
        );

        if (decision > 0) {
          return {
            success: true,
            message: 'Money has been transferred successfully',
          };
        } else {
          throw new InternalServerErrorException(
            'Payment Could not be completed',
          );
        }
      } else {
        throw new BadRequestException('Password did not matched!');
      }
    } catch (e) {
      throw new InternalServerErrorException(
        'Merchant Controller Create Billing Error = ' + e.message,
      );
    }
  }

  @Post('/add_money/bank_to_wallet')
  @UseGuards(AuthGuard)
  @UsePipes(new ValidationPipe())
  @HttpCode(HttpStatus.OK) // Set the status code to 200 (OK)
  async Bank_to_Wallet(
    @Request() req,
    @Body() bill: Payment_ReceiverDTO,
  ): Promise<any> {
    try {
      const user_validity_decision = await this.merchantService.user_validity(
        req.user.email,
        bill.password,
      );

      if (user_validity_decision) {
        bill.payment_type = 'Bank to Wallet';
        const decision = await this.merchantService.Add_Credits_Amount(
          req.user.email,
          bill,
        );

        if (decision > 0) {
          return {
            success: true,
            message: 'Money has been transferred successfully',
          };
        } else {
          throw new InternalServerErrorException(
            'Payment Could not be completed',
          );
        }
      } else {
        throw new BadRequestException('Password did not matched!');
      }
    } catch (e) {
      throw new InternalServerErrorException(
        'Merchant Controller Create Billing Error = ' + e.message,
      );
    }
  }

  @Get('payment/list')
  @UseGuards(AuthGuard)
  @UsePipes(new ValidationPipe())
  @HttpCode(HttpStatus.OK) // Set the status code to 200 (OK)
  async Get_All_Billing(@Request() req): Promise<any> {
    try {
      const payment_list = this.merchantService.Get_All_Billing_Payment(
        req.user.email,
      );

      if (payment_list != null) {
        return payment_list;
      } else {
        throw new NotFoundException('Data not found');
      }
    } catch (e) {
      throw new InternalServerErrorException(e.message);
    }
  }

  @Post('/forget_password')
  @UsePipes(new ValidationPipe())
  @HttpCode(HttpStatus.OK) // Set the status code to 200 (OK)
  async Forget_Password(
    @Body() forgetPassword_DTO: ForgetPasswordDTO,
  ): Promise<any> {
    try {
      return await this.merchantService.ForgetPassword(
        forgetPassword_DTO.email,
      );
    } catch (e) {
      throw new InternalServerErrorException(e.message);
    }
  }

  @Post('/otp')
  @UsePipes(new ValidationPipe())
  @HttpCode(HttpStatus.OK) // Set the status code to 200 (OK)
  async OTP_Verification(
    @Request() req,
    @Body() OTP_Object: OTP_ReceiverDTO,
  ): Promise<any> {
    try {
      console.log('User provided otp = ' + OTP_Object.otp);
      const deicision = await this.merchantService.otp_verification(
        req,
        OTP_Object.otp,
      );
      if (deicision) {
        return {
          success: true,
          message: 'OTP verification successful',
        };
      } else {
        return new BadRequestException('OTP did not matched!');
      }
    } catch (e) {
      // throw new InternalServerErrorException(e.message);
    }
  }
}
